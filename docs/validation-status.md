# Validation status — 2026-11-11

This is a public summary of local maintainer qualification and recorded external Multi-PC fleet evaluations. Private toolchain paths, raw logs, generated binaries, internal plans, and incoming external attacker workspaces remain outside public handoff bundles.

## 1. External Multi-PC Attacker Fleet Qualification (`V16.0` – `V19.0` — Phase 4 Completed)

Across 8 consecutive external 5-PC attacker fleet rounds (`40` independent blind target evaluations totaling `~30.6` attacker-hours and `5,087` observed reversing tool calls across REA MCP, Ghidra headless decompilation, Unicorn CPU emulation, and differential probing):

| Validated Scope | Engine Generation | Functional Parity | Interactive / Batch Usability | Standalone External Recovery |
| --- | --- | --- | --- | --- |
| 11 Supported Languages (`c`, `cpp`, `rust`, `swift`, `go`, `csharp`, `java`, `kotlin`, `python`, `javascript`, `typescript`) | `antirea-rust-v19` (`Format v19`) | `100%` (`5,198` pairs / route) | `11 / 11 USABLE` (`3.19 ms` – `6.97 ms`) | `0 / 11` (`0%`) |
| 5 Real Open-Source C Libraries (`LZ4`, `xxHash`, `Lua 5.4`, `BLAKE3`, `SQLite 3.46.1`) with Auto Ontology Scope | `antirea-rust-v16` – `v19` | `100%` | `5 / 5 USABLE` (`0.63 ms` – `5.06 ms`; `32.4x` – `4,345.7x` speedup vs. naive hot-loop VM) | `0 / 5` (`0%`) |
| 323-Node Multi-Channel Flagship Core & 4-Subsystem Commercial Enterprise Suite | `antirea-rust-v18` – `v19` | `100%` (`5,198` pairs / `18,991` tx) | `USABLE` (`0.37 ms/call` flagship; `15.72 ms` suite) | `0%` (`0 / 40` cumulative across 8 rounds) |
| NVIDIA Auto Ontology Semantic Layer (`v1.2.0` + `auto-ontology-eval`) | `V16.0` – `V20.0` catalog | `28 / 28` (`100.0%`) treatment vs. `11 / 28` (`39.3%`) schema-only | `0` broken-run failures, `0` regressions | Read-only SQLite `set_authorizer` enforced |

## 2. Newly Implemented Phase 5 / `v1.1.0` Capabilities (Locally Verified — External Fleet `not_evaluated`)

Per repository policy (`AGENTS.md`), local build/functional/structural verification is strictly separated from external Multi-PC attacker fleet evaluation:

| Capability | Local Verification Evidence (Windows x64) | External Attacker Fleet Status |
| --- | --- | --- |
| **Pure-Rust Engine `V20.0` (`antirea-rust-v20`, `Format v20`)**: `V20-M1` (`_mm_unpackhi_epi64` zero `pshufd 0xee` & zero `{11,17}` fallback rotations), `V20-M2` (`portable_simd128` 256-vector bit-exact SSE2 equivalence, cross-OS `.lib`/`lib*.a` & binary seed scan), `V20-M3` (live `.rdata` ciphertext digest ratchet) | `cargo test --manifest-path rust/Cargo.toml` (`15 / 15` passed), `0` seed leakage hits | **`not_evaluated`** (`verified_fleet_rounds = 0` in `antirea.ontology`) |
| **Direct Cargo Library Crate VM Route (`compile-cargo` & `compile_cargo_crate_vm`)**: Automatic LLVM IR emission, Auto Ontology hot-loop exclusion, and `antirea-rust-v20` staticlib compilation | `tests/test_rust_multilang.py` (`5 / 5` passed on live Cargo crate) | **`not_evaluated`** |
| **8-Layer C & LLVM IR Hardening (`antirea/hardening.py`)**: SHA-256 CSPRNG parameter/seed derivation, `anti_dump` volatile ephemeral scrub & pool integrity guard, `iat_api_hiding` internal symbol-table hash resolver, LLVM IR C-string XOR encryption & MBA instruction lowering | `tests/test_hardening.py` (`21 / 21` passed including Clang `-O2` DLL execution) & `tests/test_diversify.py` (`29 / 29` passed) | **`not_evaluated`** |

## 3. Implementation and Trust Limits

- Functional preservation and static structural checks do **not** by themselves establish resistance against external AI reverse-engineering agents; newly added `V20.0` and `hardening.py` transforms remain marked `not_evaluated` until run against the isolated Multi-PC attacker fleet.
- While `V20-M2` provides a pure-Rust `portable_simd128` polyfill verified bit-for-bit against hardware `x86_64` SSE2 across 256 randomized 128-bit lane vectors and cross-OS staticlib/binary hygiene helpers, native `aarch64` Linux/macOS host linking and execution still require physical/CI target-host qualification.
- Direct Cargo crate VM compilation (`compile-cargo` / `compile_cargo_crate_vm`) targets VM-lowerable scalar/pointer library functions (`antirea-ir`); arbitrary generic/async whole-workspace Rust binaries remain scoped through boundary library crates.

For commands and language contracts, see [multi-language development](multilanguage-development.md). For C/IR hardening layer details, see [hardening capabilities](hardening-capabilities.md).
