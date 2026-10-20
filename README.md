**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Türkçe](docs/readme/README_tr.md) · [Русский](docs/readme/README_ru.md) · [Tiếng Việt](docs/readme/README_vi.md) · [ไทย](docs/readme/README_th.md) · [Deutsch](docs/readme/README_de.md) · [Español](docs/readme/README_es.md) · [Français](docs/readme/README_fr.md) · [Українська](docs/readme/README_uk.md) · [Polski](docs/readme/README_pl.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [العربية](docs/readme/README_ar.md) · [فارسی](docs/readme/README_fa.md) · [Bahasa Indonesia](docs/readme/README_id.md) · [Italiano](docs/readme/README_it.md) · [Ελληνικά](docs/readme/README_el.md) · [മലയാളം](docs/readme/README_ml.md)

# ANTI-REA

<!-- gitreels:start -->
<p align="center">
  <a href="https://gitreels.com/chldbwnstm/ANTI-REA"><img src="https://gitreels.com/chldbwnstm/ANTI-REA.webp" alt="chldbwnstm/ANTI-REA in 15 seconds" width="100%"></a>
  <br>
  <a href="https://gitreels.com"><img src="https://gitreels.com/badge.svg" alt="Made with GitReels" height="24"></a>
</p>
<!-- gitreels:end -->

### One MCP for protecting binaries, applications, and core logic against REA.

**Have a core feature you need to protect? Keep it from being analyzed or cloned, down to the binary level.**

[![Defense vs REA](https://img.shields.io/badge/Defense_vs_REA-25%25-4bbd9c?style=flat-square)](#current-defense--roadmap-testapp-vm-vs-live-rea-attacks)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

Reverse-engineering tools like [REA](https://github.com/morluto/rea) let an agent inspect a binary when you ask *"Understand how this feature works in that app and build a copy for my project."*

**Agentic attack? Meet agentic defense — defense that grows stronger over time.** The ultimate goal of **ANTI-REA** is to **block everything that REA can analyze**. Ask your agent in plain language — *"Protect the core logic in my program so REA can't analyze or clone it"* — and the agent locates your core functions and surrounding clues, applies obfuscation and virtualization (VM), verifies that behavior isn't broken, and measures what percentage of the original speed it runs at.

You don't need to build a complex attack-and-defense lab yourself. **Every day, we pit our defense environment against a separate REA attack environment on TestApp's VM, inspect how attacks break through, patch the weak spots, and continuously strengthen the defense.** You simply connect the battle-hardened ANTI-REA to your agent and use it.

---

## Current Defense & Roadmap (TestApp VM vs. Live REA Attacks)

![TestApp VM Defense vs. REA 25%](docs/assets/defense-roadmap.svg)

This gauge is not an abstract project schedule — it represents **how well our VM-protected TestApp holds up against direct attacks from REA on a separate environment**.

### Defense Stages (Ultimate Goal: Block Everything REA Analyzes)

- **25% (Current) · First-Stage Static Reconstruction Blocked:** Starting from a baseline VM that was easily broken, handler diversification and operand context coupling now prevent external REA static analysis from reconstructing the core formula in one shot.
- **50% · Block Static Analysis & Context Inference:** Hide internal dispatcher helpers and call-graph clues so the original logic cannot be inferred from static decompilation alone.
- **75% · Defend Against Dynamic Tracing & Debugging:** Protect core logic and constants when attackers turn to debuggers, Frida, execution traces, and memory dumps.
- **100% · Full Defense Across Everything REA Analyzes:** Extend protection beyond native binaries (C/C++, Rust, Go) to .NET, Java/Kotlin, JavaScript/Electron, Python, and macOS (Mach-O/ARM64), blocking REA across every target and analysis path it supports.

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

![ANTI-REA Overview](docs/assets/antirea-overview.svg)

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

While the built-in open-source **`ANTI-REA Engine`** grows stronger every day (combining a 16-bit polymorphic register-fused VM, silent anti-debug key poisoning, anti-tamper hash-to-key binding, MBA & opaque predicates, encrypted constant pools + IAT hiding, and anti-LLM honeypot decoys), **if you need even stronger protection right now, you can purchase Themida, VMProtect, or Code Virtualizer, connect it to ANTI-REA, and simply tell your agent in natural language what execution speed and defense level you want.**

```text
Use VMProtect (or Themida / Code Virtualizer) to keep execution speed above 80% of the original while defending the core logic as strongly as possible.
```

| Engine | Connection | Current Status |
|---|---|---|
| **ANTI-REA Engine** | Built-in C++/LLVM VM & 6-layer hardening pipeline | Active polymorphic VM protection, silent anti-debug/anti-tamper key poisoning, MBA/opaque predicates, anti-LLM honeypots, and automated verification on Windows x86-64 C++ |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **VMProtect** | Defense MCP/CLI (`.vmp` project) | Windows native x86/x64 PE adapter implemented (requires local installation) |
| **Code Virtualizer** | Defense MCP/CLI (`.cv` project) | Windows native x86/x64 PE adapter implemented (Legacy / v4 supported, requires local installation) |

---

## Development & Testing

Run the unit and boundary test suite from the repository root:

```powershell
python -m unittest discover -s tests -v
```

Contributions for commercial protector verification, new VM obfuscation ideas, general project build integration, and macOS support are welcome. Distributed under the [MIT License](LICENSE) (connected third-party protection engines follow their own respective licenses; initial LLVM pass pipeline includes components derived from open-source Kagura under MIT).
