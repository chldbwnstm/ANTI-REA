[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · **العربية** · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### خادم MCP واحد لحماية الملفات الثنائية والتطبيقات والمنطق الأساسي من تحليل REA.

**هل لديك ميزة أساسية تريد حمايتها؟ امنع تحليلها أو استنساخها حتى المستوى الثنائي (Binary).**

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


## البدء السريع

### 1. التثبيت وربط الوكيل (`Set up your agent`)

لا حاجة لكتابة أوامر الطرفية أو تعديل ملفات الإعداد يدوياً؛ فقط اطلب من وكيلك (Claude Code أو Cursor أو Codex أو Gemini CLI إلخ):

```text
قم بتثبيت ANTI-REA في بيئة Python افتراضية محلية (.venv) واربط خادم antirea.defense_mcp بإعدادات MCP لديك لتتمكن من استخدامه فوراً.
```

### 2. اطلب من وكيلك باللغة الطبيعية (`Ask your agent`)

```text
احمِ منطق الحساب الأساسي والقرائن المحيطة به في مشروعي حتى لا يتمكن REA من تحليلها أو استنساخها، وأخبرني ما إذا كانت الوظيفة الأصلية سليمة وكم تبلغ نسبة سرعة التشغيل مقارنة بالسرعة الأصلية.
```

```text
أنشئ أولاً خطة حماية لملف app.exe باستخدام VMProtect واعرضها عليّ، ونفذها بعد موافقتي.
```

### 3. الاستخدام المباشر عبر الطرفية (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## كيف يعمل وكيف يزداد قوة كل يوم

![ANTI-REA Overview](../../docs/assets/antirea-overview.svg)

| Iteration | Protection | REA Outcome |
|---|---|---|

---

## المحركات المدعومة

بينما يزداد المحرك مفتوح المصدر المدمج (`ANTI-REA Engine`) قوة كل يوم، **إذا كنت بحاجة إلى حماية أقوى الآن، يمكنك شراء Themida أو VMProtect أو Code Virtualizer وربطه بـ ANTI-REA، ثم إخبار وكيلك باللغة الطبيعية بمستوى سرعة الأداء وقوة الدفاع التي تريدها.**

```text
استخدم VMProtect (أو Themida / Code Virtualizer) للحفاظ على سرعة التشغيل فوق 80% من السرعة الأصلية مع حماية المنطق الأساسي بأقصى درجة ممكنة.
```

| Engine | Connection | Status |
|---|---|---|
| **ANTI-REA Engine** | C++/LLVM defense pipeline | Active VM protection, automated verification & daily hardening (Windows x86-64) |
| **Themida** | Defense MCP/CLI (`.tmd`/`.tm`) | Windows native x86/x64 PE adapter implemented |
| **VMProtect** | Defense MCP/CLI (`.vmp`) | Windows native x86/x64 PE adapter implemented |
| **Code Virtualizer** | Defense MCP/CLI (`.cv`) | Windows native x86/x64 PE adapter implemented |

---

## التطوير والاختبار

```powershell
python -m unittest discover -s tests -v
```

يُوزع هذا المشروع بموجب ترخيص [MIT License](../../LICENSE) (تخضع محركات الحماية المرتبطة لتراخيصها الخاصة).
