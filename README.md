**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Türkçe](docs/readme/README_tr.md) · [Русский](docs/readme/README_ru.md) · [Tiếng Việt](docs/readme/README_vi.md) · [ไทย](docs/readme/README_th.md) · [Deutsch](docs/readme/README_de.md) · [Español](docs/readme/README_es.md) · [Français](docs/readme/README_fr.md) · [Українська](docs/readme/README_uk.md) · [Polski](docs/readme/README_pl.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [العربية](docs/readme/README_ar.md) · [فارسی](docs/readme/README_fa.md) · [Bahasa Indonesia](docs/readme/README_id.md) · [Italiano](docs/readme/README_it.md) · [Ελληνικά](docs/readme/README_el.md) · [മലയാളം](docs/readme/README_ml.md)

# ANTI-REA

### One MCP for protecting binaries, applications, and core logic against REA.

**Have a core feature you need to protect? Keep it from being analyzed or cloned, down to the binary level.**

[![Version](https://img.shields.io/badge/Version-v1.0.0-10b981?style=flat-square)](CHANGELOG.md)
[![Defense Status](https://img.shields.io/badge/Defense_Status-Phase_4_Active-38bdf8?style=flat-square)](#anti-rea-evolution-roadmap)
[![Rust Engine](https://img.shields.io/badge/Rust_Engine-antirea--rust--v19_(1.75%2B_MSVC)-dea584?style=flat-square&logo=rust&logoColor=white)](#supported-engines)
[![Auto Ontology](https://img.shields.io/badge/Semantic_Scope-NVIDIA_Auto_Ontology_1.2-76b900?style=flat-square)](#semantic-scope--rsi-lineage-nvidia-auto-ontology)
[![Languages](https://img.shields.io/badge/Languages-11_Supported-007acc?style=flat-square)](#supported-programming-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Rust_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

Reverse-engineering tools like [REA](https://github.com/morluto/rea) let an agent inspect a binary when you ask *"Understand how this feature works in that app and build a copy for my project."*

**Agentic attack? Meet agentic defense — defense that grows stronger over time.** The ultimate goal of **ANTI-REA** is to **block everything that REA can analyze**. Ask your agent in plain language — *"Protect the core logic in my program so REA can't analyze or clone it"* — and the agent uses ANTI-REA's semantic scope analyzer (powered by [NVIDIA Auto Ontology](https://github.com/NVIDIA/auto-ontology)) to isolate secret/boundary functions without trapping inner hot loops, compiles them through the Pure-Rust polymorphic VM (`antirea-rust-v19`, `Format v19`), verifies bit-exact behavioral equivalence, and measures interactive and batch execution speed.

---

## What Gets Protected in Your Software?

- **Core Algorithms & Business Logic:** Prevents proprietary calculations, data processing formulas, and core intellectual property from being decompiled, reverse-engineered, or cloned.
- **Secret Data & Embedded Keys:** Protects sensitive API credentials, encryption keys, tokens, and proprietary constants from being extracted in plaintext from `.rdata` or post-prologue memory dumps.
- **License & Authorization Checks:** Shields premium feature gates, expiration timers, and product activation checks against cracker bypasses, binary tampering, or forced branch flipping.
- **Anti-Tampering & Memory Dump Defense:** Defeats static `.rdata` extraction, post-prologue RAM/stack snapshots, differential trace correlation, and isolated Unicorn CPU handler probing while remaining strictly `W^X` compliant (no `RWX` / `VirtualProtect` pages).
- **Internal Call Graphs & Execution Flow:** Fuses cross-channel wrappers and inlines leaf helpers (`0` internal cluster `call`s) behind polymorphic non-16 cluster topologies (`12..20` clusters + medium-tier `.pdata` bridges) so analysts cannot map structural call blueprints.
- **Automated AI Cloning & REA Defense:** Directly neutralizes autonomous AI reverse-engineering agents (REA + Ghidra + Unicorn dynamic probing) even when our full open-source compiler (`rust/crates/antirea-passes`) is public (**Kerckhoffs's Principle**).

---

## Supported Programming Languages

ANTI-REA unifies core logic virtualization across **11 native, managed, and dynamic languages** through its Pure-Rust polymorphic VM compiler (`antirea-rust-v19` via `antirea-cli compile-multilang` and `antirea.rust_multilang`):

| Language | Environment / Runtime | Protection Mechanism (`antirea-rust-v19`) | Deployment Form |
|:---|:---|:---|:---|
| **C** | Clang / MSVC / LLVM | LLVM IR → Auto Ontology Scope → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Standalone Native Binary (`.exe`) & Native DLL |
| **C++** | Clang++ / MSVC / LLVM | LLVM IR → Auto Ontology Scope → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Standalone Native Binary (`.exe`) & Native DLL |
| **Rust** | `rustc` / Cargo / LLVM | Rust LLVM IR → Auto Ontology Scope → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | C-ABI & Standalone Protected Native Binary |
| **Swift** | Swift 5.x+ (LLVM Native) | Swift Frontend IR → Auto Ontology Scope → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Native App Core & Protected Executable |
| **Go** | Go 1.20+ (Typed Native) | Pure-Go Numeric AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Package Core Separation & Native Binary Link |
| **C# (.NET)** | .NET 8 / 9 (CLR / IL) | C# / CIL Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Managed App + Protected Native Core (P/Invoke / EXE) |
| **Java** | OpenJDK 17+ / JVM | Java Bytecode / Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Java Application + JNI / Protected Native Core |
| **Kotlin** | Kotlin 1.9+ / JVM | Kotlin / JVM Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) | Kotlin App / JVM Service + Protected Native Core |
| **Python** | Python 3.10 ~ 3.13 | Python AST Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) & Mixed Native Bundle | Protected Native Binary / PYD Extension & Module Bundle |
| **JavaScript** | Node.js / Electron / Runtime | JS Core AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) & Native Addon Bridge | Protected Native Core & Application Bundle |
| **TypeScript** | TypeScript 5.x+ | Typed TS AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v19`) & Native Addon Bridge | Protected Native Core & Transpiled Bundle |

> [!TIP]
> For detailed architectural contracts and language integration specifications, see [Multi-Language Development](docs/multilanguage-development.md).

---

## ANTI-REA Evolution Roadmap

![ANTI-REA Cosmic Defense Roadmap](docs/assets/defense-roadmap.svg)

- **Phase 1 · Focus on Static Binary Protection [COMPLETED]:** Protects compiled native binaries against static decompilation, Ghidra analysis, and direct formula recovery via control-flow virtualization and layered binary hardening.
- **Phase 2 · Deep Static Hardening [COMPLETED]:** Extends static resilience by camouflaging handler boundaries, scrambling symbol relations, and concealing dispatcher internals.
- **Phase 3 · Scaling Automated Attack Testers [COMPLETED]:** Continuously scales up autonomous attack agent instances, pitting new defense iterations against live automated testers every day to evolve defenses automatically.
- **Phase 4 · Dynamic Protection Hardening, Semantic Auto Ontology & Pure-Rust Engine `V19` Evolution [ACTIVE]**
- **Phase 5 · ? [Classified]**
- **Phase 6 · ? [Classified]**
- **Phase 7 · ? [The Frontier]**

---

## Quick start

### 1. Set up your agent

No need to manually install prerequisites, run terminal commands, or edit config files. Just ask your agent (Claude Code, Cursor, Codex, Gemini CLI, etc.) and it will check and install any missing prerequisites (Rust 1.75+ `x86_64-pc-windows-msvc`, LLVM/Clang, MSVC Build Tools, Python 3.11+), build the Pure-Rust defense engine, and connect both the Defense MCP (`antirea.defense_mcp`) and Read-Only Semantic Ontology MCP (`antirea.ontology_mcp`) servers automatically:

```text
Check and install any missing prerequisites (Rust toolchain, LLVM/Clang, MSVC linker, and Python 3.11+), install ANTI-REA in a local Python virtual environment (.venv), build the release Rust defense engine (cargo build --release --manifest-path rust/Cargo.toml), and connect antirea.defense_mcp and antirea.ontology_mcp to your MCP configuration so you can use them right away.
```

### 2. Ask your agent

Once connected, ask your agent in natural language:

```text
Protect the core calculation logic and surrounding clues in my project so REA cannot analyze or clone them, keep inner hot loops fast using Auto Ontology scope analysis, and tell me if the original behavior is 100% intact and what speed it runs at.
```

Or if you already have a built executable and a commercial protector profile:

```text
Create a VMProtect protection plan for app.exe, show it to me first, and run it once I approve.
```

Your agent automatically queries the read-only semantic layer (`recommend_scope`, `check_readiness` in `antirea.ontology_mcp`) and calls `antirea.defense_mcp` tools to inspect available engines (`protection_doctor`), generate a fingerprinted source or binary plan (`protection_source_plan` / `protection_plan`), build/protect after approval (`protection_source_build` / `protection_protect`), and verify output equivalence and speed (`protection_source_validate` / `protection_benchmark`).

### 3. Use the terminal

Build the Pure-Rust defense engine (`antirea-cli`), select budget-safe virtualization boundaries with Auto Ontology, and compile hardened `antirea-rust-v19` targets:

```powershell
# 1. Build the Pure-Rust defense engine workspace
cargo build --release --manifest-path rust/Cargo.toml

# 2. Recommend optimal protection scope on any LLVM IR module (excludes inner hot-loop traps)
.\.venv\Scripts\python.exe -m antirea.ontology_mcp --ir <module.ll> recommend-scope --max-slowdown 15

# 3. Compile selected LLVM IR function(s) into a hardened Pure-Rust polymorphic VM staticlib (antirea-rust-v19)
.\rust\target\release\antirea-cli.exe compile-multilang --workspace . --input-ir <module.ll> --dispatchers <fn1,fn2> --output-dir <out_dir> --seed 90720261105

# 4. Full end-to-end candidate build + 4-gate verification against baseline and previous executables
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --previous <prev.exe> --output-dir <out_dir> --seed 90720261105
```

Inspect providers, check semantic ontology readiness, sync upstream `NVIDIA/auto-ontology` releases, or run the 28-task deterministic A/B semantic evaluation directly from the terminal:

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
.\.venv\Scripts\python.exe -m antirea.ontology_mcp readiness
.\.venv\Scripts\python.exe -m antirea.auto_ontology_sync sync --check-remote
.\.venv\Scripts\python.exe -m antirea.ontology_eval
```

- [How to Run](docs/how-to-run.md) · [Protection Bridge](docs/protection-bridge.md) · [Toolchain Setup](docs/toolchain.md) · [Reference](docs/reference.md)

---

## Semantic Scope & RSI Lineage (NVIDIA Auto Ontology)

Applying VM virtualization blindly to an entire library virtualizes inner data-loop helpers (such as `XXH64_round`, `counter_low`, `luaV_shiftl`, or `sqlite3VarintLen` — small functions that have no loop backedge themselves yet execute millions of times inside caller loops), causing `174x`–`41,743x` latency spikes (`UNUSABLE`).

ANTI-REA integrates **[NVIDIA Auto Ontology](https://github.com/NVIDIA/auto-ontology)** (`v1.2.0`) and **`auto-ontology-eval`** (`antirea.ontology`, `antirea.ontology_mcp`, `antirea.auto_ontology_sync`, `antirea.ontology_eval`) to compile LLVM IR call/loop graphs, 11-language lowering routes, real OSS benchmarks, and structured RSI foothold-to-mitigation lineage into a certified read-only SQLite + `AutoOntologyModelDocument` semantic layer:

- **Zero-Config Transitive Hot-Loop Detection:** Statically identifies natural-loop backedges, 3-hop transitive loop-invoked leaf helpers (`called_from_loop`, including compiler-synthesized JVM/Python/JS/TS lowered helpers), and `antirea-ir` VM lowerability without manual policy files.
- **Algebraic Symmetric-Boundary Hardening (`ONTO-SYM-V3`):** Detects aligned bit-slice symmetric `XOR`/`ADD` input combinations (`has_symmetric_input_mix`) in boundary functions and automatically pairs them with non-commutative caller-callee modular ring pre-mixing to prevent differential arity collapse.
- **Strictly Read-Only SQLite MCP & Safe Upstream Sync:** `antirea.ontology_mcp` enforces a SQLite `set_authorizer` (`SELECT`/`READ`/`FUNCTION` only, blocking all `INSERT`/`UPDATE`/`DELETE`/`DDL`/`PRAGMA` mutations) across 10 read-only MCP tools, while `antirea.auto_ontology_sync` fast-forwards upstream `NVIDIA/auto-ontology` updates (`core.hooksPath=NUL`) with automatic rollback if breaking schema or grader changes occur.
- **Verified `auto-ontology-eval` A/B Accuracy (`+60.7%p`):** Across 28 deterministic tasks spanning 7 tables (`simple`, `moderate`, `challenging`), the Auto Ontology semantic layer achieves **`28 / 28` (`100.0%`)** exact execution match vs. **`11 / 28` (`39.3%`)** for raw schema-only queries, with **`0` regressions**.

### Real-World Open-Source C Protection Speedup (`Naive VM` vs. `Auto Ontology + antirea-rust-v19`)

Even when inner data-processing loops remain native `-O2` for throughput, virtualizing Auto Ontology's selected key-derivation and boundary finalization functions keeps **standalone external attacker recovery at `0%`** while accelerating real workloads by **`32.4x` to `4,345.7x`**:

| Open-Source Target | Real-World Workload | Naive Hot-Loop VM | **Auto Ontology + `antirea-rust-v19`** | **Speedup vs. Naive** | External Attacker Recovery |
|:---|:---|---:|---:|---:|:---:|
| **`LZ4`** | 128 KB `LZ4F` frame compress/decompress + checksum | `3,389.67 ms` (`UNUSABLE`) | **`0.78 ms` (`USABLE`)** | **`4,345.7x`** | **`0%` (Blocked)** |
| **`xxHash`** | 256 KB `XXH64` streaming digest | `1,637.45 ms` (`UNUSABLE`) | **`0.63 ms` (`USABLE`)** | **`2,586.8x`** | **`0%` (Blocked)** |
| **`Lua 5.4`** | 2,500-round 64-bit ARX VM execution + GC | `551.00 ms` (`UNUSABLE`) | **`3.00 ms` (`USABLE`)** | **`183.7x`** | **`0%` (Blocked)** |
| **`BLAKE3`** | 256 KB keyed Merkle-tree chunk stream | `323.22 ms` (`UNUSABLE`) | **`3.15 ms` (`USABLE`)** | **`102.7x`** | **`0%` (Blocked)** |
| **`SQLite 3.46.1`** | 2,000-row B-Tree `INSERT` + indexed query (`2,482` IR fns) | `164.13 ms` | **`5.06 ms` (`USABLE`)** | **`32.4x`** | **`0%` (Blocked)** |

---

## Multi-Language, Real OSS & Commercial Enterprise Verification (`antirea-rust-v19`)

Every supported language route, complex multi-function flagship core, real open-source library, and multi-subsystem enterprise binary protected by `antirea-rust-v19` (`Format v19`) is validated across our **Multi-PC parallel external attacker fleet** (REA MCP + Ghidra headless decompilation + Unicorn CPU emulation + differential probing):

| # | Language / Target | Frontend → `antirea-rust-v19` Pipeline | Polymorphic Cluster Topology | Functional Equivalence | Verified Latency | External REA Recovery | Usability Status |
|:-:|:---|:---|:---:|:---:|:---:|:---:|:---:|
| 1 | **C** | Clang `-O1 -emit-llvm` → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.54 ms` | **`0%` (Blocked)** | `USABLE` |
| 2 | **C++** | Clang++ `-std=c++17 -emit-llvm` → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.29 ms` | **`0%` (Blocked)** | `USABLE` |
| 3 | **Rust** | `rustc --emit=llvm-ir` → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.73 ms` | **`0%` (Blocked)** | `USABLE` |
| 4 | **Swift** | `swiftc -emit-ir` → LLVM Normalize → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.50 ms` | **`0%` (Blocked)** | `USABLE` |
| 5 | **Go** | Go AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `5.33 ms` | **`0%` (Blocked)** | `USABLE` |
| 6 | **C# (.NET)** | C# Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.53 ms` | **`0%` (Blocked)** | `USABLE` |
| 7 | **Java** | Java Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `3.19 ms` | **`0%` (Blocked)** | `USABLE` |
| 8 | **Kotlin** | Kotlin Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.77 ms` | **`0%` (Blocked)** | `USABLE` |
| 9 | **Python** | Python AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `5.57 ms` | **`0%` (Blocked)** | `USABLE` |
| 10 | **JavaScript** | JS AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `4.81 ms` | **`0%` (Blocked)** | `USABLE` |
| 11 | **TypeScript** | TS Typed AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v19` | `1` VM / `12..20` clusters | `100%` (`5,198` pairs) | `6.97 ms` | **`0%` (Blocked)** | `USABLE` |
| ◆ | **323-Node Multi-Channel Flagship Core** | Whole-Program `f1..f4` Channel Fusion → `antirea-rust-v19` | `1` Fused VM / `12..20` + Bridges | `100%` (`5,198` pairs) | `0.37 ms/call` (`750 ms` / `2,048` batch) | **`0%` (Blocked)** | `USABLE` |
| ★ | **Commercial Enterprise Suite** | 4 Subsystems (`LICENSE` · `ENTITLE` · `CLEAR` · `AUDIT`) → Pure-Rust VM | `8` VM Units / Polymorphic | `100%` (`18,991` tx) | `15.72 ms` | **`0%` (Blocked)** | `USABLE` |

---

## How It Works & How It Gets Stronger Daily

![ANTI-REA Overview](docs/assets/antirea-overview.svg)

### On Your Machine
- **Semantic Scope Beyond a Single Function:** Hiding one function leaves callers, constants, or symmetric parameter combines exposed—while hiding inner loops destroys performance. ANTI-REA traces LLVM IR call/data graphs and Auto Ontology loop attributes to select surrounding boundary clues while keeping tight loops native.
- **Plan Before Execution:** Input hashes and commands are locked into an immutable fingerprinted plan first so an agent never overwrites binaries unexpectedly.
- **Bit-Exact Equivalence & Usability Speed Gates:** Every build verifies `100%` output equivalence across thousands of randomized and boundary test vectors, enforces zero seed-byte leakage in the compiled PE, and measures interactive/batch execution speed (`usability-telemetry.json`) to guarantee `USABLE` responsiveness.

### Our Continuous Multi-PC Live Attack-Defense RSI Loop
We run a closed-loop evolutionary cycle between our **Defense Environment** and an isolated **Multi-PC Parallel External Attack Fleet (REA + Ghidra + Unicorn + Dynamic Differential Probing)**:

1. **Build & 4-Gate Validation (Pure-Rust Defense Engine):** Synthesize new Pure-Rust VM/obfuscation passes (`rust/crates/antirea-passes`) and enforce 100% behavioral equivalence, PE constant/seed hygiene, polymorphic cross-seed distinctness, and usability latency gates (`antirea-validate`).
2. **Multi-PC Blind External Attack & Telemetry:** Publish only the **protected EXE and public I/O contract** (never source code, IR, or private tests) to isolated attacker machines. Each attacker records live usability telemetry (`usability-telemetry.json`) and attempts logic recovery using REA MCP, Ghidra headless decompilation, Unicorn CPU emulation, and differential memory/stack probing, logging observed footholds in `reversing-chain.json`.
3. **Ontology-Indexed Counter-Exploitation (`V13` → `V19.0`):** Defender-curated structural footholds (`F0`–`F14`) and mitigations (`V15`–`V19`, `ONTO-SYM-V3`) are indexed in the Auto Ontology SQLite lineage catalog so open attack surfaces are systematically eliminated and re-audited across subsequent external attack rounds.

### Kerckhoffs's Principle: Why Open-Source Defense Remains Resilient Against AI Deobfuscators
Because ANTI-REA is open-source, an attacker (or an autonomous AI agent) can read our entire compiler transformation source (`rust/crates/antirea-passes/src/lib.rs`). By **Kerckhoffs's Principle**, `antirea-rust-v19` (`Format v19`) relies solely on the per-build cryptographic `--seed` and mathematically irreversible synthesis:

- **RFC 8439 20-Round `ChaCha20Csprng` & 512-Bit Sponge Whitening (`V12-M1` / `V13-M1`, Zero Seed Inversion):** Replaces reversible PRNGs (`SplitMix64`, LCG, Xorshift) with an **RFC 8439 20-round ChaCha20 stream generator (`ChaCha20Csprng`) + non-invertible 512-bit ARX sponge whitening**, paired with an automated post-link PE scan verifying `0` leaked seed bytes. Extracting every constant in `.text`/`.rdata` cannot invert the PRNG state or derive sibling keys.
- **Polymorphic `VmCtx` Layout, Variable Non-16 Cluster Topology, & `.pdata` Spectrum Smoothing (`V12-M2` / `V16-M3` / `V17-M2..M4`):** Every build Fisher-Yates shuffles `#[repr(C)]` `VmCtx` fields, randomizes arena sizes (`1,088..1,280` qwords) and `.rdata` constant pools (`288..512` qwords), synthesizes a build-unique cluster count (`12..20` leaf cluster handlers rather than a fixed `16`) routed through a vault-encrypted `ANTIREA_CLUSTER_LUT`, and emits `8–45 KB` medium-tier callable `.pdata` bridge procedures to eliminate bimodal function-size gaps.
- **On-Demand Ephemeral S-Box Vault (`W^X`), Galois LFSR Prologue, & Position-Coupled `route_slot_mask` (`V14-M1` / `V18-M2` / `V19-M1`):** Substitution tables (`VM_SBOX_ENC`) are never stored in plaintext in `.rdata` or kept unpacked in RAM; leaf handlers decrypt permutations transiently on the stack and wipe them via `core::ptr::write_volatile(..., 0)` before returning. Prologue initialization steps through primitive-polynomial $\text{GF}(2^9)/\text{GF}(2^8)$ Galois LFSRs, and `VmCtx.route_lut[0..255]` applies a nonlinear per-index `route_slot_mask(idx)` (`V19-M1`) to defeat cross-input differential byte-mask correlation.
- **4-Way Pure Leaf Inlining (`0` Internal Calls), Per-Build ChaCha20 SSE2 Bijections, & Adaptive Cluster Locality (`V14-M2` / `V18-M3` / `V19-M2`):** All leaf helpers and multi-export channels (`f1..f4`) are `#[inline(always)]`-fused into pure leaf cluster handlers (`0` internal `call` instructions), adaptive run-length cluster locality cuts 323-node flagship batch latency by `3.69x`, and every build synthesizes ChaCha20-derived 4-lane bijective SSE2 `pshufd` immediates and distinct `64-bit` shift pairs (`V19-M2`, `0` fixed legacy `0xb1`/`0x4e`/`0x39`/`0xd2` signatures).
- **96-Word 3-Share Mixed-Modulus ($\text{GF}(2) \times \mathbb{Z}_{2^{64}}$) Header Splitting, Full-64-Bit `hdr_route` Blinding, & Volatile Frame Scrubbing (`V14-M3` / `V18-M1` / `V19-M3`):** Logical header keys are split across 3 shares `(s0 ^ s1.rotate_left(r1)).wrapping_sub(s2.rotate_right(r2))` with `99.5%` (`414 / 416` qwords) pre-cluster input diffusion, caller stack argument spill slots and keyed `compile-multilang` decoy ABI registers are volatile-scrubbed (`V18-M1`), and `VmCtx.hdr_route` is dynamically blinded across all 64 bits via $\text{GF}(2)$-homomorphic shift triples (`V19-M3`).

### Multi-Generation External Attack & RSI Verification (`V13` → `V14.2` → `V16–V18` → `V19.0`)

Tested across **isolated 5-PC parallel external attacker evaluations** equipped with **REA MCP, Ghidra headless decompilation, Unicorn CPU emulation, instruction/API hooking, and differential memory/stack probing** (including an 8-cycle, `40`-evaluation continuous RSI campaign totaling `~30.6` attacker-hours and `5,087` observed reversing tool invocations across `207,920` verified I/O pairs):

| Evaluation Metric | V13 (Dynamic Attack Baseline) | V14.2 (Leaf Inlining + S-Box Vault) | V16.0 – V18.0 (6-Cycle RSI + Auto Ontology) | **V19.0 (`Format v19` — Current)** |
|:---|:---:|:---:|:---:|:---:|
| **Standalone Logic Recovery (`recovered`)** | `2 / 5` (`c`, `rust`) | **`0 / 5` (`0%`)** | **`0 / 30` (`0%` across 6 rounds)** | **`0 / 10` (`0%`; `0 / 40` Cumulative Campaign)** |
| **Plaintext S-Box / Uniform Vault Byte-Mask Leak** | `256B` Plaintext in `.rdata` | `0` Plaintext (`W^X` Stack Wipe) | `0` Plaintext + $\text{GF}(2^9)$ Galois LFSR | **`0` Plaintext + Nonlinear Per-Index `route_slot_mask` (`V19-M1`)** |
| **VM Cluster Topology & Internal `call` Graph** | Fixed `16` Clusters, `32+` `call`s | Fixed `16` Clusters, `0` `call`s | **`12..20` Polymorphic Clusters + `.pdata` Bridges, `0` `call`s** | **`12..20` Clusters + Vault LUT + Keyed Decoy ABI, `0` `call`s** |
| **SIMD / Header Route Fingerprint Surface** | Static Templates | Static SSE2 `pshufd` + Low-7b `hdr_route` | Per-Site Odd Rotations + Frame Arg Scrub | **Per-Build ChaCha20 SSE2 Bijections (`V19-M2`) + Full-64b `hdr_route` Blinding (`V19-M3`)** |
| **Real OSS Speedup & Attacker-Side `USABLE` Rate** | `3 / 5 USABLE` | `5 / 5 USABLE` (Synthetic) | **`30 / 30 USABLE` (`32.4x`–`4,345.7x` OSS Speedup; `3.69x` Flagship)** | **`10 / 10 USABLE` (`40 / 40 = 100%` Campaign; `11/11` Languages + `5/5` OSS)** |

**The more protection failures you report through Issues, the stronger ANTI-REA becomes.**

---

## Supported Engines

While the built-in open-source Pure-Rust engine (`ANTI-REA Engine`, `rust/` workspace: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`, currently **`antirea-rust-v19`** / `Format v19`) grows stronger continuously across all 11 supported languages, real open-source C libraries, and multi-module native binaries, **if you want to combine commercial binary protectors, you can connect Themida, VMProtect, or Code Virtualizer to ANTI-REA and tell your agent in natural language what execution speed and defense level you want.**

```text
Use VMProtect (or Themida / Code Virtualizer) to keep execution speed above 80% of the original while defending the core logic as strongly as possible.
```

| Engine | Connection | Current Status |
|---|---|---|
| **ANTI-REA Engine** | In-house Pure-Rust native protection workspace (`rust/`: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`), 11-language `compile-multilang` VM pipeline, & NVIDIA Auto Ontology (`antirea.ontology_mcp`) | Active Pure-Rust **`antirea-rust-v19` (`Engine V19.0`, `Format v19`)**: RFC 8439 20-round `ChaCha20Csprng` + 512-bit sponge whitening, polymorphic `12..20` leaf cluster handlers (`0` internal calls) + medium-tier `.pdata` bridges, `W^X` ephemeral stack S-Box vault + nonlinear per-index `route_slot_mask`, 96-word 3-share mixed-modulus ($\text{GF}(2) \times \mathbb{Z}_{2^{64}}$) header splitting + full-64-bit `hdr_route` blinding, per-build ChaCha20 SSE2 `pshufd` bijections, NVIDIA Auto Ontology (`v1.2.0`) scope optimization (`32.4x`–`4,345.7x` OSS speedup), and `0 / 40` recovery across 8 external 5-PC attack cycles |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **VMProtect** | Defense MCP/CLI (`.vmp` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **Code Virtualizer** | Defense MCP/CLI (`.cv` project) | Windows native x86/x64 PE adapter implemented (Legacy / v4 supported, requires local installation) |

---

## Development & Testing

Run the Pure-Rust workspace unit tests, fast core & ontology verification gates, or the full Python unit/boundary test suite from the repository root:

```powershell
# Pure-Rust VM compiler, IR lowering, and validator unit tests
cargo test --manifest-path rust/Cargo.toml

# Fast verification gates (version sync, Auto Ontology semantic layer, Defense MCP, scope & multilang)
python -m unittest discover -s tests -p "test_version_sync.py" -v
python -m unittest discover -s tests -p "test_auto_ontology.py" -v
python -m unittest discover -s tests -p "test_defense_mcp.py" -v
python -m unittest discover -s tests -p "test_scope.py" -v

# Full multi-language & integration test discovery
python -m unittest discover -s tests -v
```

Contributions for commercial protector verification, new Rust VM obfuscation passes, Auto Ontology semantic attributes, general project build integration, and macOS/Linux support are welcome. Distributed under the [MIT License](LICENSE) (connected third-party protection engines follow their own respective licenses).
