[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · **Türkçe** · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### İkili dosyaları, uygulamaları ve çekirdek mantığı REA analizinden koruyan tek bir MCP.

**Korumak istediğiniz kritik bir özelliğiniz mi var? İkili (binary) seviyeye kadar analiz edilmesini ve kopyalanmasını engelleyin.**

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


## Hızlı Başlangıç

### 1. Kurulum ve Ajan Bağlantısı (`Set up your agent`)

Terminal komutları veya yapılandırma dosyalarıyla uğraşmanıza gerek yok. Ajanınıza (Claude Code, Cursor, Codex, Gemini CLI vb.) doğrudan şunu söyleyin:

```text
ANTI-REA'yı yerel bir Python sanal ortamına (.venv) kur ve hemen kullanabilmen için antirea.defense_mcp sunucusunu MCP'ye bağla. (Also automatically check/install any missing Rust, LLVM/Clang, MSVC, and Python 3.11+ prerequisites and run `cargo build --release --manifest-path rust/Cargo.toml`.)
```

### 2. Ajanınıza Doğal Dille Komut Verin (`Ask your agent`)

```text
Projemdeki çekirdek hesaplama mantığını ve çevresel ipuçlarını REA'nın analiz edip kopyalayamayacağı şekilde koru; orijinal işlevin bozulup bozulmadığını ve çalışma hızının orijinalin yüzde kaçı olduğunu bana söyle.
```

```text
app.exe için VMProtect ile önce bir koruma planı oluşturup bana göster, onayladığımda çalıştır.
```

### 3. Doğrudan Terminalden Kullanım (`Use the terminal`)

```powershell
cargo build --release --manifest-path rust/Cargo.toml
.\rust\target\release\antirea-cli.exe compile-multilang --input-ll <vm_input.ll> --output-dir <out_dir> --seed 90720261101
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --output-dir <out_dir> --seed 90720261101
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## Nasıl Çalışır ve Her Gün Nasıl Güçlenir?

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

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

## Desteklenen Motorlar

Yerleşik açık kaynak motoru (`ANTI-REA Engine`) her gün güçlenirken, **hemen şimdi daha güçlü bir korumaya ihtiyacınız varsa Themida, VMProtect veya Code Virtualizer'ı satın alıp bağlayabilir ve ANTI-REA üzerinden istediğiniz çalışma performansını ve savunma seviyesini ajanınıza doğal dille yazabilirsiniz.**

```text
Çalışma hızını orijinalin %80'inin üzerinde tutarken çekirdek mantığı mümkün olduğunca güçlü korumak için VMProtect (veya Themida / Code Virtualizer) kullan.
```

| Engine | Connection | Status |
|---|---|---|
| **ANTI-REA Engine** | Pure-Rust Workspace (`rust/`: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`) & 11-Language `compile-multilang` VM Pipeline | Pure-Rust `antirea-rust-v12` engine (Kerckhoffs 512-bit sponge CSPRNG, polymorphic `VmCtx` shuffling, single-call inlined Feistel return sealing, tableless 16-cluster superinstruction VM, split `u128`+SSE2 `XMM` state, multi-blob commercial application support, and 4-gate + attacker usability verification) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## Geliştirme ve Test

```powershell
cargo test --manifest-path rust/Cargo.toml
python -m unittest discover -s tests -v
```

Bu proje [MIT Lisansı](../../LICENSE) altında dağıtılmaktadır (bağlanan koruma motorları kendi lisanslarına tabidir).
