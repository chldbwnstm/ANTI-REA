[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 保护二进制文件、应用程序与核心逻辑免受 REA 分析的统一 MCP。

**有想要保护的核心功能吗？从二进制层面防止它被分析或克隆。**

[![Version](https://img.shields.io/badge/Version-v1.0.0-10b981?style=flat-square)](../../CHANGELOG.md)
[![Defense Status](https://img.shields.io/badge/Defense_Status-Phase_4_Active-38bdf8?style=flat-square)](#anti-rea-evolution-roadmap)
[![Rust Engine](https://img.shields.io/badge/Rust_Engine-antirea--rust--v19_(1.75%2B_MSVC)-dea584?style=flat-square&logo=rust&logoColor=white)](#supported-engines)
[![Auto Ontology](https://img.shields.io/badge/Semantic_Scope-NVIDIA_Auto_Ontology_1.2-76b900?style=flat-square)](#semantic-scope--rsi-lineage-nvidia-auto-ontology)
[![Languages](https://img.shields.io/badge/Languages-11_Supported-007acc?style=flat-square)](#supported-programming-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Rust_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

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
> For detailed architectural contracts and language integration specifications, see [Multi-Language Development](../../docs/multilanguage-development.md).

---

## ANTI-REA Evolution Roadmap

![ANTI-REA Cosmic Defense Roadmap](../assets/defense-roadmap.svg)

- **Phase 1 · Focus on Static Binary Protection [COMPLETED]:** Protects compiled native binaries against static decompilation, Ghidra analysis, and direct formula recovery via control-flow virtualization and layered binary hardening.
- **Phase 2 · Deep Static Hardening [COMPLETED]:** Extends static resilience by camouflaging handler boundaries, scrambling symbol relations, and concealing dispatcher internals.
- **Phase 3 · Scaling Automated Attack Testers [COMPLETED]:** Continuously scales up autonomous attack agent instances, pitting new defense iterations against live automated testers every day to evolve defenses automatically.
- **Phase 4 · Dynamic Protection Hardening, Semantic Auto Ontology & Pure-Rust Engine `V19` Evolution [ACTIVE]**
- **Phase 5 · ? [Classified]**
- **Phase 6 · ? [Classified]**
- **Phase 7 · ? [The Frontier]**

---


## 快速开始

### 1. 安装并连接智能体 (`Set up your agent`)

无需手动输入终端命令或修改配置文件，直接用自然语言对你的智能体（Claude Code、Cursor、Codex、Gemini CLI 等）说：

```text
检查并自动安装缺失的必备工具（Rust 工具链、LLVM/Clang、MSVC 构建工具、Python 3.11+），将 ANTI-REA 安装到本地 Python 虚拟环境 (.venv) 中，构建纯 Rust 防御引擎 (cargo build --release --manifest-path rust/Cargo.toml)，并把 antirea.defense_mcp / antirea.ontology_mcp 服务器连接到 MCP，以便你直接使用。
```

### 2. 用自然语言指挥智能体 (`Ask your agent`)

配置完成后，直接用自然语言提出要求即可：

```text
保护我项目中的核心计算逻辑和周边线索，防止被 REA 分析和克隆，并告诉我原有功能是否正常、运行速度是原来的百分之多少。
```

如果你已经有编译好的可执行文件和商业保护工具配置，也可以这样说：

```text
先用 VMProtect 为 app.exe 制定一份保护计划给我看，等我批准后再执行。
```

### 3. 在终端直接使用 (`Use the terminal`)

```powershell
cargo build --release --manifest-path rust/Cargo.toml
.\.venv\Scripts\python.exe -m antirea.ontology_mcp --ir <module.ll> recommend-scope --max-slowdown 15
.\rust\target\release\antirea-cli.exe compile-multilang --workspace . --input-ir <module.ll> --dispatchers <fn1,fn2> --output-dir <out_dir> --seed 90720261105
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --previous <prev.exe> --output-dir <out_dir> --seed 90720261105
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
.\.venv\Scripts\python.exe -m antirea.ontology_mcp readiness
.\.venv\Scripts\python.exe -m antirea.auto_ontology_sync sync --check-remote
.\.venv\Scripts\python.exe -m antirea.ontology_eval
```

---

## 工作原理与每日攻防循环

![ANTI-REA 概览](../assets/antirea-overview.svg)

- **探索核心函数之外的周边线索：** 只隐藏一个核心函数很容易通过前后调用代码或常量被推导出逻辑。ANTI-REA 会沿着 LLVM IR 的调用关系和数据流找出需要一并隐藏的周边函数。
- **先确认计划再安全执行：** 预先锁定输入文件哈希和执行命令生成计划（Plan），仅在批准后执行。
- **功能保持与速度比例测量：** 启用 VM 必然会带来性能开销。ANTI-REA 会检查保护后的输出是否与原版完全一致，并测量运行速度相当于原版的百分之多少。

---

### Semantic Scope & RSI Lineage (NVIDIA Auto Ontology)

Applying VM virtualization blindly to an entire library virtualizes inner data-loop helpers (such as `XXH64_round`, `counter_low`, `luaV_shiftl`, or `sqlite3VarintLen`), causing `174x`–`41,743x` latency spikes (`UNUSABLE`). ANTI-REA integrates **[NVIDIA Auto Ontology](https://github.com/NVIDIA/auto-ontology)** (`v1.2.0`) and **`auto-ontology-eval`** (`antirea.ontology`, `antirea.ontology_mcp`, `antirea.auto_ontology_sync`, `antirea.ontology_eval`) to compile LLVM IR call/loop graphs, 11-language lowering routes, real OSS benchmarks, and structured RSI foothold-to-mitigation lineage into a certified read-only SQLite + `AutoOntologyModelDocument` semantic layer:

- **Zero-Config Transitive Hot-Loop & Symmetric-Boundary Analysis (`ONTO-SYM-V3`):** Statically identifies natural-loop backedges, 3-hop transitive loop-invoked helpers (`called_from_loop`, including lowered JVM/Python/JS/TS helpers), `antirea-ir` VM lowerability, and aligned bit-slice symmetric `XOR`/`ADD` boundaries paired with non-commutative caller-callee modular ring pre-mixing.
- **Strictly Read-Only SQLite MCP & Safe Upstream Sync:** `antirea.ontology_mcp` enforces a SQLite `set_authorizer` (`SELECT`/`READ`/`FUNCTION` only) across 10 read-only MCP tools, while `antirea.auto_ontology_sync` fast-forwards upstream `NVIDIA/auto-ontology` updates (`core.hooksPath=NUL`) with automatic rollback on breaking changes. Across 28 `auto-ontology-eval` tasks, the semantic layer scores **`28 / 28` (`100.0%`)** vs. **`11 / 28` (`39.3%`)** raw schema-only (`+60.7%p`, `0` regressions).

| Open-Source Target | Real-World Workload | Naive Hot-Loop VM | **Auto Ontology + `antirea-rust-v19`** | **Speedup vs. Naive** | External Attacker Recovery |
|:---|:---|---:|---:|---:|:---:|
| **`LZ4`** | 128 KB `LZ4F` frame compress/decompress + checksum | `3,389.67 ms` (`UNUSABLE`) | **`0.78 ms` (`USABLE`)** | **`4,345.7x`** | **`0%` (Blocked)** |
| **`xxHash`** | 256 KB `XXH64` streaming digest | `1,637.45 ms` (`UNUSABLE`) | **`0.63 ms` (`USABLE`)** | **`2,586.8x`** | **`0%` (Blocked)** |
| **`Lua 5.4`** | 2,500-round 64-bit ARX VM execution + GC | `551.00 ms` (`UNUSABLE`) | **`3.00 ms` (`USABLE`)** | **`183.7x`** | **`0%` (Blocked)** |
| **`BLAKE3`** | 256 KB keyed Merkle-tree chunk stream | `323.22 ms` (`UNUSABLE`) | **`3.15 ms` (`USABLE`)** | **`102.7x`** | **`0%` (Blocked)** |
| **`SQLite 3.46.1`** | 2,000-row B-Tree `INSERT` + indexed query (`2,482` IR fns) | `164.13 ms` | **`5.06 ms` (`USABLE`)** | **`32.4x`** | **`0%` (Blocked)** |

### Multi-Language, Real OSS & Commercial Enterprise Verification (`antirea-rust-v19`)

Every supported language pipeline, 323-node flagship core, real open-source C engine, and multi-module commercial subsystem protected by `antirea-rust-v19` (`Format v19`) is validated across our **Multi-PC parallel external attacker fleet** (REA MCP + Ghidra headless decompilation + Unicorn CPU emulation + differential probing):

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

### Kerckhoffs's Principle (Open-Source White-Box Defense · `antirea-rust-v19`)

Even though ANTI-REA is open-source (`rust/crates/antirea-passes/src/lib.rs` is fully public to attackers and AI agents), **Kerckhoffs's Principle** guarantees that compiled `antirea-rust-v19` (`Format v19`) binaries cannot be inverted without the secret build `--seed`:
- **RFC 8439 20-Round `ChaCha20Csprng` & 512-Bit Sponge Whitening (`V12-M1` / `V13-M1`):** Replaces reversible PRNGs (`SplitMix64`, LCG, Xorshift) with an RFC 8439 20-round ChaCha20 stream generator + non-invertible 512-bit ARX sponge whitening and an automated PE `0`-seed-leakage gate.
- **Polymorphic `VmCtx` Layout, Non-16 Cluster Topology (`12..20`), & `.pdata` Bridges (`V12-M2` / `V16-M3` / `V17-M2..M4`):** Fisher-Yates shuffles `#[repr(C)]` `VmCtx` fields, randomizes arena (`1,088..1,280` qwords) and `.rdata` (`288..512` qwords) pools, synthesizes `12..20` leaf clusters routed via a vault-encrypted `ANTIREA_CLUSTER_LUT`, and emits `8–45 KB` medium-tier `.pdata` bridges.
- **On-Demand Ephemeral S-Box Vault (`W^X`), Galois LFSR Prologue, & Nonlinear `route_slot_mask` (`V14-M1` / `V18-M2` / `V19-M1`):** Decrypts substitution tables transiently on the stack (`write_volatile` zero-wipe), steps prologue init via $\text{GF}(2^9)/\text{GF}(2^8)$ Galois LFSRs, and masks `VmCtx.route_lut[0..255]` with a position-coupled nonlinear `route_slot_mask(idx)`.
- **Pure Leaf Inlining (`0` Internal Calls), Per-Build ChaCha20 SSE2 Bijections, & Full-64-Bit `hdr_route` Blinding (`V14-M2..M3` / `V18-M1,M3` / `V19-M2..M3`):** Fuses all leaf helpers (`0` internal `call`s) with adaptive run-length cluster locality (`3.69x` faster flagship batch), 96-word 3-share mixed-modulus ($\text{GF}(2) \times \mathbb{Z}_{2^{64}}$) header splitting, volatile caller-frame scrubbing, per-build ChaCha20 SSE2 `pshufd` 4-lane bijections, and dynamic $\text{GF}(2)$-homomorphic full-64-bit `VmCtx.hdr_route` blinding.

### Multi-Generation External Attack & RSI Verification (`V13` → `V14.2` → `V16–V18` → `V19.0`)

| Evaluation Metric | V13 (Dynamic Baseline) | V14.2 (Leaf Inlining + Vault) | V16.0 – V18.0 (6-Cycle RSI + Ontology) | **V19.0 (`Format v19` — Current)** |
|:---|:---:|:---:|:---:|:---:|
| **Standalone Logic Recovery (`recovered`)** | `2 / 5` (`c`, `rust`) | **`0 / 5` (`0%`)** | **`0 / 30` (`0%` across 6 rounds)** | **`0 / 10` (`0%`; `0 / 40` Cumulative Campaign)** |
| **Vault / SIMD / `hdr_route` Fingerprint Surface** | `256B` Plaintext S-Box | `0` Plaintext (`W^X` Wipe) | `12..20` Clusters + `.pdata` Bridges + Galois LFSR | **Per-Index `route_slot_mask` + Per-Build SSE2 Bijections + Full-64b `hdr_route` Blinding** |
| **Real OSS Speedup & Attacker-Side `USABLE` Rate** | `3 / 5 USABLE` | `5 / 5 USABLE` | **`30 / 30 USABLE` (`32.4x`–`4,345.7x` OSS Speedup)** | **`10 / 10 USABLE` (`40 / 40 = 100%`; `207,920 / 207,920` Bit-Exact Pairs)** |

---

## 支持的保护引擎

内置的免费开源纯 Rust 引擎（`ANTI-REA Engine`，`rust/` 工作区 + `antirea-rust-v19` + NVIDIA Auto Ontology 语义范围优化）每天都在持续进化；**如果你想同时结合商业保护工具，也可以连接 Themida、VMProtect 或 Code Virtualizer，直接用自然语言告诉智能体你期望的运行速度比例与防御强度。**

```text
使用 VMProtect（或 Themida / Code Virtualizer），在保持运行速度不低于原版 80% 的同时，尽可能高强度地保护核心逻辑。
```

| 引擎 | 连接方式 | 当前状态 |
|---|---|---|
| **ANTI-REA Engine** | 纯 Rust 原生保护工作区 (`rust/`: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`)、11 语言 `compile-multilang` 管线与 `antirea.ontology_mcp` | Active Pure-Rust **`antirea-rust-v19` (`Engine V19.0`, `Format v19`)**: RFC 8439 20-round `ChaCha20Csprng` + 512-bit sponge whitening, polymorphic `12..20` leaf cluster handlers (`0` internal calls) + medium-tier `.pdata` bridges, `W^X` ephemeral stack S-Box vault + nonlinear per-index `route_slot_mask`, 96-word 3-share mixed-modulus ($\text{GF}(2) \times \mathbb{Z}_{2^{64}}$) header splitting + full-64-bit `hdr_route` blinding, per-build ChaCha20 SSE2 `pshufd` bijections, NVIDIA Auto Ontology (`v1.2.0`) scope optimization (`32.4x`–`4,345.7x` OSS speedup), and `0 / 40` recovery across 8 external 5-PC attack cycles |
| **Themida** | 防御 MCP/CLI (`.tmd`/`.tm`) | 已实现 Windows 原生 x86/x64 PE 适配器（需本地安装） |
| **VMProtect** | 防御 MCP/CLI (`.vmp`) | 已实现 Windows 原生 x86/x64 PE 适配器（需本地安装） |
| **Code Virtualizer** | 防御 MCP/CLI (`.cv`) | 已实现 Windows 原生 x86/x64 PE 适配器（支持 Legacy / v4，需本地安装） |

---

## 开发与测试

```powershell
cargo test --manifest-path rust/Cargo.toml
python -m unittest discover -s tests -p "test_version_sync.py" -v
python -m unittest discover -s tests -p "test_auto_ontology.py" -v
python -m unittest discover -s tests -p "test_defense_mcp.py" -v
python -m unittest discover -s tests -p "test_scope.py" -v
python -m unittest discover -s tests -v
```

欢迎贡献商业保护工具实测、新 VM 混淆思路、通用项目构建集成以及 macOS 支持。本项目基于 [MIT License](../../LICENSE) 发布（所连接的各保护引擎遵循其各自的许可证）。
