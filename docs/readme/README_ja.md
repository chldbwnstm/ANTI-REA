[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · **日本語** · [한국어](README_ko.md) · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### バイナリ、アプリケーション、コアロジックをREAの解析から守る単一のMCP。

**守りたいコア機能がありますか？バイナリレベルまで解析・複製されないように保護しましょう。**

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


## クイックスタート

### 1. インストールとエージェント接続 (`Set up your agent`)

ターミナルコマンドや設定ファイルを直接触る必要はありません。お使いのエージェント（Claude Code, Cursor, Codex, Gemini CLIなど）に次のように指示するだけで、インストールからMCPサーバー接続まで自動で行います。

```text
ANTI-REAをローカルのPython仮想環境(.venv)にインストールして、すぐに使えるように antirea.defense_mcp サーバーをMCPに接続して。
```

### 2. エージェントに自然言語で指示する (`Ask your agent`)

設定が終わったら、複雑なオプションを覚えることなく自然言語で依頼できます。

```text
プロジェクトのコア計算ロジックと周辺の手がかりがREAに解析・複製されないように保護をかけて、元の機能が壊れていないかと、実行速度が元の何%で動くか教えて。
```

ビルド済みの実行ファイルと商用プロテクター設定がある場合は、次のようにも依頼できます：

```text
app.exeにVMProtectで保護計画を先に立てて見せて。承認したら実行して。
```

### 3. ターミナルから直接使う (`Use the terminal`)

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 仕組みと毎日の防御強化ループ

![ANTI-REA 概要](../../docs/assets/antirea-overview.svg)

- **コア関数だけでなく周辺の手がかりまで保護範囲を探索：** コア関数1つだけを隠しても、前後の呼び出しや定数から推測されてしまいます。LLVM IRの呼び出し関係とデータを辿り、一緒に隠すべき周辺関数を特定します。
- **計画確認後の安全な実行：** 入力ファイルのハッシュと実行コマンドを事前に計画（Plan）として固定し、承認された処理のみを実行します。
- **機能保持と速度比率の測定：** VMを適用すると実行速度にオーバーヘッドが生じます。保護後も元のバイナリと出力が完全一致するかを検査し、実行速度が元の何%で動作するかを測定して報告します。

| 回次 / 実験 | 適用した保護 | REA攻撃結果と観察 |
|---|---|---|

---

## 対応エンジン

標準搭載の無料・オープンソースエンジン（`ANTI-REA Engine 補強`）も毎日強化されていますが、**今すぐさらに強力な保護が必要な場合は、Themida、VMProtect、Code Virtualizerを有料で購入して接続し、ANTI-REAを通じて「どの程度の実行性能（速度維持率）とどの程度の防御強度を望むか」を自然言語でエージェントに伝えるだけで使えます。**

```text
VMProtect（または Themida / Code Virtualizer）を使って、実行速度は元の80%以上を維持しつつ、コアロジックを最大限強く防御して。
```

| エンジン | 接続方式 | 現在の対応状況 |
|---|---|---|
| **ANTI-REA Engine 補強** | C++/LLVMビルドおよび防御パイプライン | Windows x86-64 C++サンプルへのVM適用、機能・性能自動検査、毎日の防御強化を適用中 |
| **Themida** | 防御MCP/CLI（`.tmd`/`.tm`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（ローカル環境へのインストールが必要） |
| **VMProtect** | 防御MCP/CLI（`.vmp`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（ローカル環境へのインストールが必要） |
| **Code Virtualizer** | 防御MCP/CLI（`.cv`） | Windowsネイティブ x86/x64 PEアダプタ実装済み（Legacy / v4対応、ローカルインストールが必要） |

---

## 開発とテスト

```powershell
python -m unittest discover -s tests -v
```

商用プロテクター連携の再現、新しいVM難読化のアイデア、一般プロジェクトのビルド接続、macOS対応などのコントリビューションを歓迎します。本プロジェクトは [MIT License](../../LICENSE) の下で配布されています（連携する各保護エンジンはそれぞれのライセンスに従います）。
