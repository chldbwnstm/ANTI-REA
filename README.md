**English** · [简体中文](docs/readme/README_zh.md) · [繁體中文](docs/readme/README_zh-TW.md) · [日本語](docs/readme/README_ja.md) · [한국어](docs/readme/README_ko.md) · [Türkçe](docs/readme/README_tr.md) · [Русский](docs/readme/README_ru.md) · [Tiếng Việt](docs/readme/README_vi.md) · [ไทย](docs/readme/README_th.md) · [Deutsch](docs/readme/README_de.md) · [Español](docs/readme/README_es.md) · [Français](docs/readme/README_fr.md) · [Українська](docs/readme/README_uk.md) · [Polski](docs/readme/README_pl.md) · [Português (Brasil)](docs/readme/README_pt-BR.md) · [العربية](docs/readme/README_ar.md) · [فارسی](docs/readme/README_fa.md) · [Bahasa Indonesia](docs/readme/README_id.md) · [Italiano](docs/readme/README_it.md) · [Ελληνικά](docs/readme/README_el.md) · [മലയാളം](docs/readme/README_ml.md)

# ANTI-REA

### One MCP for protecting binaries, applications, and core logic against REA.

**Have a core feature you need to protect? Keep it from being analyzed or cloned, down to the binary level.**

[![Defense Status](https://img.shields.io/badge/Defense_Status-Phase_2_Active-38bdf8?style=flat-square)](#anti-rea-evolution-roadmap)
[![Languages](https://img.shields.io/badge/Languages-11_Supported-007acc?style=flat-square)](#supported-programming-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#quick-start)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#quick-start)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#supported-engines)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)

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
> For detailed architectural contracts and language integration specifications, see [Multi-Language Development](docs/multilanguage-development.md).

---

## ANTI-REA Evolution Roadmap

![ANTI-REA Cosmic Defense Roadmap](docs/assets/defense-roadmap.svg)

- **Phase 1 · Focus on Static Binary Protection [COMPLETED]:** Protects compiled native binaries against static decompilation, Ghidra analysis, and direct formula recovery via control-flow virtualization and layered binary hardening.
- **Phase 2 · Deep Static Hardening [ACTIVE]:** Extends static resilience with independent per-function VM dispatchers, instruction fusion, bytecode checksum key binding, and symbol relation obfuscation.
- **Phase 3 · Scaling Automated Attack Testers [NEXT · Daily Evolving]:** Continuously scales up autonomous attack agent instances, pitting new defense iterations against live automated testers every day to evolve defenses automatically.
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

For a supported source project, use `protection_languages`, `protection_source_plan`, `protection_source_build`, and the separate execution step `protection_source_validate`. `protection_bindings` generates native-core integration code. For a commercial binary protector, use `protection_doctor`, `protection_plan`, and `protection_protect` after reviewing the plan.

The built-in engine requires source input. Built-in `auto-protect` for an already compiled EXE is unsupported and returns `blocked` / `source_project_required`; it does not transform or benchmark the input against itself as a protected result.

### 3. Use the terminal

You can also inspect supported providers and local setup directly from the terminal:

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

For the native, C# and JVM source routes, first configure the pinned local LLVM/Kagura toolchain and Windows SDK, plus the source-language compiler. Planning does not compile or execute target source; JS/TS inspection runs a pinned installed parser. Validation explicitly executes owned originals and protected artifacts in child processes. Python and JS/TS use separate AST/VM backends without a native compiler. None of these commands publishes an artifact.

```powershell
python -m antirea.defense_mcp languages
python -m antirea.defense_mcp source-plan --project samples/multilang/native/c/project.json --seed 1729
# Review the returned plan and substitute its exact plan_id and fingerprint:
python -m antirea.defense_mcp source-build --plan-id <plan_id> --fingerprint <fingerprint>
python -m antirea.defense_mcp source-validate --plan-id <plan_id> --contract samples/multilang/native/contract.json --random-cases 8192
python -m antirea.defense_mcp bindings --contract samples/multilang/native/contract.json
```

Run these with the configured Python environment from the repository root. `<plan_id>` and `<fingerprint>` are placeholders, not literal PowerShell arguments. See [multi-language development](docs/multilanguage-development.md) for manifest fields, prerequisites, validation limits and evidence.

### Current multi-language foundation

| Capability | Verified scope as of 2026-10-22 | Not established |
|---|---|---|
| Native source protection | C, multi-source C++, and single-crate Rust integer C-ABI cores; fresh Windows x64 public workflows each matched 8,200 inputs across independently source-compiled original, baseline and protected DLLs ([evidence](docs/validation-status.md)) | General application linking, Cargo production builds, arbitrary runtime features, macOS |
| Surrounding-function scope | Reviewed C/C++ policy protects a core plus callers/helpers before optimization; a three-file fixture covers four internal functions and an excluded public forwarder | Complete semantic clue detection or automatic shared-data encryption |
| C# source protection | Restricted static integer IL → C → native VM; baseline/protected matched original CLR on 8,516 distinct inputs for each of three methods | Whole .NET assemblies, managed objects |
| C# app integration | Explicit [source-integrate](docs/csharp-applications.md) rewrites supported method bodies to native calls; fresh public build, ten app cases and three-file deployment relocation passed | Restricted integer leaves and a console sample; not arbitrary csproj/MSBuild, whole-assembly or GUI compatibility |
| Java/Kotlin source protection | Actual `.java` and `.kt` sources → restricted JVM bytecode → C → native VM; each language's three exports matched original JVM execution on 8,516 inputs per export, including a protected private helper | Whole JARs/classes, objects, automatic call-site replacement |
| Java/Kotlin app integration | Explicit [source-integrate](docs/jvm-applications.md) preserves ordinary caller bytecode and replaces core implementations with JNI-backed facades; fresh Java and Kotlin builds each passed 11 app cases and 11 relocated-bundle cases | Restricted scalar cores and owned source apps; not arbitrary JAR/Gradle/Maven, reflection detection, whole-language or macOS compatibility |
| Go source protection | Actual `go/parser` + `go/types` frontend → fixed-width integer C → native VM; four exports and one helper protected, 68,128 original-Go/native comparisons passed | Core imports, objects, concurrency and general projects; ordinary app connection uses the separate route below |
| Swift source protection | Actual Swift compiler → closed scalar LLVM graph → native VM; u32/i32/u64/i64 exports and their helpers protected, 136,256 original-Swift/native comparisons passed | Checked overflow, objects/runtime calls, whole apps, macOS |
| Go/Swift app integration | Explicit [source-integrate](docs/go-swift-applications.md) preserves app source bytes and replaces separated cores with same-name native facades; fresh Go/Swift builds passed 17/15 app cases and 17/15 copied-deployment cases, with missing/unset-core controls | Windows x64 scalar-core console samples; not arbitrary Go modules, SwiftPM, concurrency, whole-language or macOS compatibility |
| Python source protection | Restricted integer/bool AST → encoded Python VM, now with per-function flattened dispatch engines; pure and [mixed-module](docs/python-mixed-modules.md) routes retain both original/protected repeat observations | Whole packages, arbitrary libraries and native Kagura hardening are not established; generated-source structure is not attack-resistance evidence |
| JavaScript/TypeScript source protection | Restricted source → encoded JavaScript VM with per-function flattened dispatch engines; [mixed-module builds and explicit JS/TS validation](docs/javascript-mixed-modules.md) preserve unselected code and compare declared scalar functions; TS uses an independently transpiled reference | Sampled agreement is not whole-app equivalence. Arbitrary TS source graphs, objects, native Kagura hardening, full TS type checking and external resistance are not established |
| Python/JS/TS app integration | Explicit [source-integrate](docs/multilanguage-development.md#script-application-integration) stages an ordinary app around one protected module; fresh Python/JS/TS workflows passed 4/15/13 cases across original, protected and copied-deployment arms, plus missing-module controls | Owned Windows CLI samples, not arbitrary packages, browsers, whole-app equivalence, performance acceptance or REA resistance |
| Native-core bindings | Generators and plain-ABI execution checked in all 11 language IDs, including Windows/amd64 Go and portable Swift | Protection of the calling language's original source; other OS/architecture validation |
| Protected-library integration | Python, Node, Java, Kotlin, TypeScript and C# called a protected C DLL; Go and Swift callers additionally checked protected native libraries against their baselines | Whole-application equivalence or attack resistance; binding checks remain separate from source protection |

Native builds use explicit selection or a reviewed C/C++ scope policy. Neither discovers the full semantic protection boundary automatically. All language routes remain experimental subsets; bindings are a separate capability. C#/JVM/Go/Swift validation also compares both native arms against original language execution. Current fixtures have substantial measured overhead; passing correctness tests is not performance acceptance. The overall multi-language objective remains incomplete, and external resistance of these new artifacts is unmeasured.

Latest [Windows qualification record](docs/validation-status.md): 2,891 ordinary tests passed, 82 deliberate opt-in skips, plus separate actual source/app workflows. It distinguishes fresh runs, Go's successful same-build integration retry after an outer timeout, and earlier script-workflow evidence.

---

## How It Works & How It Gets Stronger Daily

![ANTI-REA Overview](docs/assets/antirea-overview.svg)

### On Your Machine
- **Scope Beyond a Single Function:** A reviewed C/C++ scope policy connects the LLVM IR planner to the source builder before optimization, selecting the core and relevant callers/helpers. Unresolved relationships require review; this is not a guarantee that all semantic clues or shared data are protected.
- **Plan Before Execution:** Input hashes and commands are locked into a plan first so the agent never overwrites binaries unexpectedly.
- **Behavior & Relative Speed Measurement:** VM protection inevitably adds overhead. ANTI-REA verifies that outputs match the original binary and measures what percentage of the original speed the protected binary achieves.

### Our Daily Live Attack-Defense Loop
We run a continuous loop between our **Defense Environment** and an **External Attack Environment (REA + Ghidra)**:

1. **Build & Verify (Defense Environment):** Apply new VM/obfuscation techniques to TestApp and verify 100% output equivalence and performance bounds across thousands of test cases.
2. **Blind Attack Test (External Attack Environment):** Share only the **protected EXE and public I/O specification** (never source code or private tests). The attack environment uses REA to analyze and reimplement the binary.
3. **Weakness Analysis & Next Defense:** Inspect the incoming attack report to see which clues leaked (constant tables, handler patterns, helper functions) and harden the next-generation VM against them.

---

## Supported Engines

The built-in open-source **`ANTI-REA Engine`** combines selected-function Kagura transformations with VM instruction fusion and per-build format diversification. Multi-function native builds can now use separate per-function codecs and dispatchers with volatile indirect calls; all four engines in the context fixture retained checksums and runtime FLA/SUB/CO and passed sampled correctness checks. These locally available engines and pointers remain recoverable. Its optional hardening names are not all implemented protections: the [capability audit](docs/hardening-capabilities.md) separates requested settings, generated helpers, retained IR and missing mechanisms. IAT hiding and anti-dump remain unimplemented, application string encryption is not supplied by synthetic helpers, and inert decoys were removed by optimization.

Themida, VMProtect and Code Virtualizer are separate local commercial-tool adapters. A requested speed or defense level is a target for evaluation, not a guarantee or a comparative result against the built-in engine. Vendor installation, licensing and per-artifact validation remain necessary.

```text
Use VMProtect (or Themida / Code Virtualizer) to keep execution speed above 80% of the original while defending the core logic as strongly as possible.
```

| Engine | Connection | Current Status |
|---|---|---|
| **ANTI-REA Engine** | Experimental C/C++/Rust/Swift and restricted C#/Java/Kotlin/Go → LLVM/native VM; restricted Python and JS/TS → language-specific VMs | Subset fixture validation and per-artifact [hardening evidence](docs/hardening-capabilities.md). Non-native VMs do not inherit native hardening. No compiled-EXE built-in protection, whole-language compatibility, macOS validation or general attack-resistance claim |
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

Implementation scope and remaining work: [multi-language development](docs/multilanguage-development.md). Requested versus verified protection components: [hardening capabilities](docs/hardening-capabilities.md).
