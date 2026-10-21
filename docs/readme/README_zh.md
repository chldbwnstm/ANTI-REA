[English](../../README.md) · **简体中文** · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 保护二进制文件、应用程序与核心逻辑免受 REA 分析的统一 MCP。

**有想要保护的核心功能吗？从二进制层面防止它被分析或克隆。**

[![Defense Status](https://img.shields.io/badge/Defense_Status-Phase_2_Active-38bdf8?style=flat-square)](#anti-rea-evolution-roadmap)
[![Languages](https://img.shields.io/badge/Languages-11_Supported-007acc?style=flat-square)](#supported-programming-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
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

ANTI-REA supports core logic virtualization and hardening across a wide spectrum of native, managed, and dynamic languages:

| Language | Environment / Runtime | Protection Mechanism | Deployment Form |
|:---|:---|:---|:---|
| **C / C++** | Clang / MSVC / LLVM | Native Polymorphic Register VM | Standalone Binary & Native DLL |
| **Rust** | `rustc` / LLVM | Native Polymorphic Register VM | C-ABI & Native Core Library |
| **Go** | Go 1.20+ (Typed Native) | Native VM + Facade Integration | Package Core Separation & Binary Link |
| **Swift** | Swift 5.x+ (LLVM Native) | Swift Native VM + App Integration | Native App Core & Dynamic Library |
| **C# (.NET)** | .NET 8 / 9 (CLR / IL) | IL Lowering → Native VM | Managed App + Protected Native Core (P/Invoke) |
| **Java** | OpenJDK 17+ / JVM | JVM Bytecode → Native VM | Java Application + JNI Native Core |
| **Kotlin** | Kotlin 1.9+ / JVM | JVM Bytecode → Native VM | Kotlin App / JVM Service Core |
| **Python** | Python 3.10 ~ 3.13 | Flattened Per-Function Stack VM | Pure Module & Mixed Module Bundle |
| **JavaScript** | Node.js / Browser / Electron | Encoded Virtualized Stack VM | CommonJS Module & App Bundle |
| **TypeScript** | TypeScript 5.x+ | TS Transpile + Encoded VM | Transpiled Bundle & Core Module |

> [!TIP]
> For detailed architectural contracts and language integration specifications, see [Multi-Language Development](../../docs/multilanguage-development.md).

---

## ANTI-REA Evolution Roadmap

![ANTI-REA Cosmic Defense Roadmap](../assets/defense-roadmap.svg)

- **Phase 1 · Focus on Static Binary Protection [COMPLETED]:** Protects compiled native binaries against static decompilation, Ghidra analysis, and direct formula recovery via control-flow virtualization and layered binary hardening.
- **Phase 2 · Deep Static Hardening [ACTIVE]:** Extends static resilience by camouflaging handler boundaries, scrambling symbol relations, and concealing dispatcher internals.
- **Phase 3 · Scaling Automated Attack Testers [NEXT]:** Continuously scales up autonomous attack agent instances, pitting new defense iterations against live automated testers every day to evolve defenses automatically.
- **Phase 4 · ? [Classified]**
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

## Current Defense vs. Live REA Attacks

![ANTI-REA Defense Strength vs. REA 25%](../assets/defense-roadmap.svg)

This gauge represents **how well our protected TestApp holds up against direct attacks from REA on a separate environment**, actively battle-tested every day.

### Protected Capabilities & Defense Scope

- **Core Logic & Algorithm Virtualization (ANTI-REA VM):** Compiles sensitive functions and control flow into a 16-bit polymorphic register-fused VM bytecode with dynamic operand context encryption, entirely eliminating raw x86/x64 machine instructions.
- **Silent Anti-Debug Key Poisoning:** Detects PEB BeingDebugged directly without IAT imports. Rather than exiting with an obvious exit() branch, it silently corrupts the VM key derivation when attached by debuggers or Frida, yielding garbage bytecode decoding without tipping off the analyst.
- **Self-Checksumming & Anti-Tampering (Hash-to-Key Binding):** Binds bytecode header integrity and prologue invariants directly into runtime key generation, preventing in-memory patching, inline hooks, and software breakpoints.
- **Mixed Boolean-Arithmetic (MBA) & Opaque Predicates:** Synthesizes polynomial boolean-algebraic identities and number-theoretic opaque predicates into VM handlers and expressions, neutralizing decompilers (Ghidra, IDA) and automated LLM-based formula recovery.
- **Encrypted Constant Pools & IAT API Hiding:** Encrypts sensitive constants and signature strings via a rolling stream cipher decrypted only on the stack on demand, resolving system calls dynamically via symbol hashes to keep the Import Address Table clean.
- **Anti-LLM Honeypots & Decoy Ciphers:** Injects realistic decoy Feistel ciphers and fake S-box constant tables behind opaque never-taken branches, forcing autonomous AI reverse-engineering agents like REA to waste analysis time and token budgets on decoys.

---

## 开发与测试

```powershell
python -m unittest discover -s tests -v
```

欢迎贡献商业保护工具实测、新 VM 混淆思路、通用项目构建集成以及 macOS 支持。本项目基于 [MIT License](../../LICENSE) 发布（所连接的各保护引擎遵循其各自的许可证）。
