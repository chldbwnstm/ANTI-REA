[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 保护二进制文件、应用程序与核心逻辑免受 REA 分析的统一 MCP。

**有想要保护的核心功能吗？从二进制层面防止它被分析或克隆。**

[![Defense Status](https://img.shields.io/badge/Defense_Status-Phase_4_Active-38bdf8?style=flat-square)](#anti-rea-evolution-roadmap)
[![Rust Engine](https://img.shields.io/badge/Rust_Engine-1.75%2B_MSVC-dea584?style=flat-square&logo=rust&logoColor=white)](#supported-engines)
[![Languages](https://img.shields.io/badge/Languages-11_Supported-007acc?style=flat-square)](#supported-programming-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Rust_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

Reverse-engineering tools like [REA](https://github.com/morluto/rea) let an agent inspect a binary when you ask *"Understand how this feature works in that app and build a copy for my project."*

**Agentic attack? Meet agentic defense — defense that grows stronger over time.** The ultimate goal of **ANTI-REA** is to **block everything that REA can analyze**. Ask your agent in plain language — *"Protect the core logic in my program so REA can't analyze or clone it"* — and the agent locates your core functions and surrounding clues, applies obfuscation and virtualization (VM), verifies that behavior isn't broken, and measures what percentage of the original speed it runs at.

---

## What Gets Protected in Your Software?

- **Core Algorithms & Business Logic:** Prevents proprietary calculations, data processing formulas, and core intellectual property from being decompiled, reverse-engineered, or cloned.
- **Secret Data & Embedded Keys:** Protects sensitive API credentials, encryption keys, tokens, and proprietary constants from being extracted in plaintext from the binary.
- **License & Authorization Checks:** Shields premium feature gates, expiration timers, and product activation checks against cracker bypasses, binary tampering, or forced branch flipping.
- **Anti-Tampering & Memory Dump Defense:** Stops attackers from attaching debuggers, injecting hooks (such as Frida), or dumping live process memory to steal unpacked code.
- **Internal Call Graphs & Execution Flow:** Conceals internal subroutines and API communication paths so competitors and analysts cannot trace the software's structural blueprint.
- **Automated AI Cloning & REA Defense:** Directly neutralizes autonomous AI reverse-engineering agents like REA that inspect binaries to replicate and reimplement your features into competing projects.

---

## Supported Programming Languages

ANTI-REA unifies core logic virtualization across **11 native, managed, and dynamic languages** through its Pure-Rust polymorphic VM compiler (`antirea-rust-v12` via `antirea-cli compile-multilang` and `antirea.rust_multilang`):

| Language | Environment / Runtime | Protection Mechanism (`antirea-rust-v12`) | Deployment Form |
|:---|:---|:---|:---|
| **C** | Clang / MSVC / LLVM | LLVM IR → ANTI-REA IR Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Standalone Native Binary (`.exe`) & Native DLL |
| **C++** | Clang++ / MSVC / LLVM | LLVM IR → ANTI-REA IR Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Standalone Native Binary (`.exe`) & Native DLL |
| **Rust** | `rustc` / Cargo / LLVM | Rust LLVM IR → ANTI-REA IR Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | C-ABI & Standalone Protected Native Binary |
| **Swift** | Swift 5.x+ (LLVM Native) | Swift Frontend IR → ANTI-REA IR Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Native App Core & Protected Executable |
| **Go** | Go 1.20+ (Typed Native) | Pure-Go Numeric AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Package Core Separation & Native Binary Link |
| **C# (.NET)** | .NET 8 / 9 (CLR / IL) | C# / CIL Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Managed App + Protected Native Core (P/Invoke / EXE) |
| **Java** | OpenJDK 17+ / JVM | Java Bytecode / Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Java Application + JNI / Protected Native Core |
| **Kotlin** | Kotlin 1.9+ / JVM | Kotlin / JVM Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) | Kotlin App / JVM Service + Protected Native Core |
| **Python** | Python 3.10 ~ 3.13 | Python AST Core Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) & Mixed Native Bundle | Protected Native Binary / PYD Extension & Module Bundle |
| **JavaScript** | Node.js / Electron / Runtime | JS Core AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) & Native Addon Bridge | Protected Native Core & Application Bundle |
| **TypeScript** | TypeScript 5.x+ | Typed TS AST Lowering → Pure-Rust Polymorphic VM (`antirea-rust-v12`) & Native Addon Bridge | Protected Native Core & Transpiled Bundle |

> [!TIP]
> For detailed architectural contracts and language integration specifications, see [Multi-Language Development](../../docs/multilanguage-development.md).

---

## ANTI-REA Evolution Roadmap

![ANTI-REA Cosmic Defense Roadmap](../assets/defense-roadmap.svg)

- **Phase 1 · Focus on Static Binary Protection [COMPLETED]:** Protects compiled native binaries against static decompilation, Ghidra analysis, and direct formula recovery via control-flow virtualization and layered binary hardening.
- **Phase 2 · Deep Static Hardening [COMPLETED]:** Extends static resilience by camouflaging handler boundaries, scrambling symbol relations, and concealing dispatcher internals.
- **Phase 3 · Scaling Automated Attack Testers [COMPLETED]:** Continuously scales up autonomous attack agent instances, pitting new defense iterations against live automated testers every day to evolve defenses automatically.
- **Phase 4 · Dynamic Protection Hardening & Pure-Rust Engine Evolution [ACTIVE]**
- **Phase 5 · ? [Classified]**
- **Phase 6 · ? [Classified]**
- **Phase 7 · ? [The Frontier]**

---


## 快速开始

### 1. 安装并连接智能体 (`Set up your agent`)

无需手动输入终端命令或修改配置文件，直接用自然语言对你的智能体（Claude Code、Cursor、Codex、Gemini CLI 等）说：

```text
将 ANTI-REA 安装到本地 Python 虚拟环境 (.venv) 中，并把 antirea.defense_mcp 服务器连接到 MCP，以便你直接使用。
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
.\rust\target\release\antirea-cli.exe compile-multilang --input-ll <vm_input.ll> --output-dir <out_dir> --seed 90720261101
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --output-dir <out_dir> --seed 90720261101
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 工作原理与每日攻防循环

![ANTI-REA 概览](../../docs/assets/antirea-overview.svg)

- **探索核心函数之外的周边线索：** 只隐藏一个核心函数很容易通过前后调用代码或常量被推导出逻辑。ANTI-REA 会沿着 LLVM IR 的调用关系和数据流找出需要一并隐藏的周边函数。
- **先确认计划再安全执行：** 预先锁定输入文件哈希和执行命令生成计划（Plan），仅在批准后执行。
- **功能保持与速度比例测量：** 启用 VM 必然会带来性能开销。ANTI-REA 会检查保护后的输出是否与原版完全一致，并测量运行速度相当于原版的百分之多少。

---

### Multi-Language & Commercial Enterprise Verification (`antirea-rust-v12`)

Every language pipeline and multi-module commercial subsystem protected by `antirea-rust-v12` is validated across our **5-PC parallel external attacker fleet** (REA MCP + Ghidra headless decompilation + dynamic probing):

| # | Language / Target | Frontend → `antirea-rust-v12` Pipeline | VM Blobs / Cluster Handlers | Functional Equivalence | Single-Call Latency | External REA Recovery | Usability Status |
|:-:|:---|:---|:---:|:---:|:---:|:---:|:---:|
| 1 | **C** | Clang `-O1 -emit-llvm` → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.54 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 2 | **C++** | Clang++ `-std=c++17 -emit-llvm` → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.29 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 3 | **Rust** | `rustc --emit=llvm-ir` → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.73 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 4 | **Swift** | `swiftc -emit-ir` → LLVM Normalize → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.50 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 5 | **Go** | Go AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `5.33 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 6 | **C# (.NET)** | C# Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.53 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 7 | **Java** | Java Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `3.19 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 8 | **Kotlin** | Kotlin Core Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.77 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 9 | **Python** | Python AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `5.57 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 10 | **JavaScript** | JS AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `4.81 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| 11 | **TypeScript** | TS Typed AST Lowering → Clang LLVM IR → ANTI-REA IR → `antirea-rust-v12` | 1 / 16 | `100%` | `6.97 ms` | **`0 / 1` (Blocked)** | `USABLE` |
| ★ | **Commercial Enterprise Suite** | 4 Subsystems (`LICENSE` · `ENTITLE` · `CLEAR` · `AUDIT`) → `antirea-rust-v12` | **8 / 128** | `100%` (`18,991` tx) | `15.72 ms` | **`0 / 5` (Blocked)** | `USABLE (5/5)` |

### Kerckhoffs's Principle (Open-Source White-Box Defense · `antirea-rust-v12`)

Even though ANTI-REA is open-source (`rust/crates/antirea-passes/src/lib.rs` is fully public to attackers and AI agents), **Kerckhoffs's Principle** guarantees that the compiled binary cannot be inverted without the secret build `--seed`:
- **One-Way 512-Bit Cryptographic Sponge CSPRNG (`V12-M1`, `KerckhoffsSpongeRng`):** Replaces reversible PRNGs (`SplitMix64`) with a non-invertible ChaCha20/BLAKE3-style ARX sponge so exposed constants cannot be inverted to recover the build seed or sibling keys.
- **Per-Build Polymorphic `VmCtx` Layout Shuffling (`V12-M2`):** Fisher-Yates shuffles `#[repr(C)]` `VmCtx` struct fields, padding arrays (`pad_lo`, `pad_hi`), and bijective header/arena permutations (`hdr_perm_mul`, `arena_perm_mul`) on every build.
- **Polymorphic Opcode Lowering (`V12-M3`) & Single-Call Inlined Transcript Coupling (`V12-M4`):** Varies operand evaluation order, self-canceling MBA identities, and chaff interleaving per instruction arm, and inlines entry-gate derivation + 4-round Feistel return unsealing into `@antirea_dispatch_<tag>` coupled via inline `%vm.st` in `@antirea_score`.

---

## 开发与测试

```powershell
cargo test --manifest-path rust/Cargo.toml
python -m unittest discover -s tests -v
```

欢迎贡献商业保护工具实测、新 VM 混淆思路、通用项目构建集成以及 macOS 支持。本项目基于 [MIT License](../../LICENSE) 发布（所连接的各保护引擎遵循其各自的许可证）。
