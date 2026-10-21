**English** · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### One MCP for protecting binaries, applications, and core logic against REA.

**Have a core feature you need to protect? Keep it from being analyzed or cloned, down to the binary level.**

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


## Quick start

### 1. Set up your agent

No need to touch terminal commands or config files manually. Just ask your agent (Claude Code, Cursor, Codex, Gemini CLI, etc.):

```text
Install ANTI-REA in a local Python virtual environment (.venv) and connect the antirea.defense_mcp server to your MCP configuration so you can use it right away.
```

### 2. Ask your agent

Once connected, ask your agent in natural language:

```text
Protect the core calculation logic and surrounding clues in my project so REA cannot analyze or clone them, and tell me if the original behavior is intact and what percentage of the original speed it runs at.
```

Or if you already have a built executable and a commercial protector profile:

```text
Create a VMProtect protection plan for app.exe, show it to me first, and run it once I approve.
```

Your agent automatically calls ANTI-REA MCP tools to check available engines (`protection_doctor`), generate a hashed execution plan (`protection_plan`), and run protection after approval (`protection_protect`).

### 3. Use the terminal

You can also inspect supported providers and local setup directly from the terminal:

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## How It Works & How It Gets Stronger Daily

![ANTI-REA Overview](../assets/antirea-overview.svg)

### On Your Machine
- **Scope Beyond a Single Function:** Hiding just one function leaves callers and constants exposed. In the LLVM IR path, ANTI-REA traces call graphs and shared data to include surrounding functions that leak clues.
- **Plan Before Execution:** Input hashes and commands are locked into a plan first so the agent never overwrites binaries unexpectedly.
- **Behavior & Relative Speed Measurement:** VM protection inevitably adds overhead. ANTI-REA verifies that outputs match the original binary and measures what percentage of the original speed the protected binary achieves.

### Our Daily Live Attack-Defense Loop
We run a continuous loop between our **Defense Environment** and an **External Attack Environment (REA + Ghidra)**:

1. **Build & Verify (Defense Environment):** Apply new VM/obfuscation techniques to TestApp and verify 100% output equivalence and performance bounds across thousands of test cases.
2. **Blind Attack Test (External Attack Environment):** Share only the **protected EXE and public I/O specification** (never source code or private tests). The attack environment uses REA to analyze and reimplement the binary.
3. **Weakness Analysis & Next Defense:** Inspect the incoming attack report to see which clues leaked (constant tables, handler patterns, helper functions) and harden the next-generation VM against them.

---

## Supported Engines

While the built-in open-source engine (`ANTI-REA Engine`) grows stronger every day, **if you need even stronger protection right now, you can purchase Themida, VMProtect, or Code Virtualizer, connect it to ANTI-REA, and simply tell your agent in natural language what execution speed and defense level you want.**

```text
Use VMProtect (or Themida / Code Virtualizer) to keep execution speed above 80% of the original while defending the core logic as strongly as possible.
```

| Engine | Connection | Current Status |
|---|---|---|
| **ANTI-REA Engine** | C++/LLVM build & defense pipeline | Active VM protection, automated verification, and daily defense hardening on Windows x86-64 C++ |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **VMProtect** | Defense MCP/CLI (`.vmp` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **Code Virtualizer** | Defense MCP/CLI (`.cv` project) | Windows native x86/x64 PE adapter implemented (Legacy / v4 supported, requires local installation) |

---

## Development & Testing

Run the unit and boundary test suite from the repository root:

```powershell
python -m unittest discover -s tests -v
```

Contributions for commercial protector verification, new VM obfuscation ideas, general project build integration, and macOS support are welcome. Distributed under the [MIT License](../../LICENSE) (connected third-party protection engines follow their own respective licenses).
