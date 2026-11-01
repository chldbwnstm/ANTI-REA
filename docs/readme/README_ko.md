[English](../../README.md) · [简体中文](README_zh.md) · [繁體中文](README_zh-TW.md) · [日本語](README_ja.md) · **한국어** · [Türkçe](README_tr.md) · [Русский](README_ru.md) · [Tiếng Việt](README_vi.md) · [ไทย](README_th.md) · [Deutsch](README_de.md) · [Español](README_es.md) · [Français](README_fr.md) · [Українська](README_uk.md) · [Polski](README_pl.md) · [Português (Brasil)](README_pt-BR.md) · [العربية](README_ar.md) · [فارسی](README_fa.md) · [Bahasa Indonesia](README_id.md) · [Italiano](README_it.md) · [Ελληνικά](README_el.md) · [മലയാളം](README_ml.md)

# ANTI-REA

### 바이너리, 애플리케이션, 핵심 로직을 REA로부터 보호하는 하나의 MCP.

**지키고 싶은 핵심 기능이 있나요? 바이너리 레벨까지 분석·복제되지 않게 보호하세요.**

[![방어 상태](https://img.shields.io/badge/Defense_Status-Phase_4_Active-38bdf8?style=flat-square)](#anti-rea-진화-로드맵)
[![Rust Engine](https://img.shields.io/badge/Rust_Engine-1.75%2B_MSVC-dea584?style=flat-square&logo=rust&logoColor=white)](#지원-엔진)
[![지원 언어](https://img.shields.io/badge/Languages-11개_언어_지원-007acc?style=flat-square)](#지원-프로그래밍-언어-supported-languages)
[![MCP + CLI](https://img.shields.io/badge/MCP-stdio_%2B_CLI-5c4ee5?style=flat-square)](#빠른-시작)
[![Python requirements](https://img.shields.io/badge/Python-3.11+-3776ab?style=flat-square&logo=python&logoColor=white)](#빠른-시작)
[![Engines](https://img.shields.io/badge/Engines-ANTI--REA_Rust_Engine_%7C_VMP_%7C_Themida_%7C_CV-cb3837?style=flat-square)](#지원-엔진)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

[REA](https://github.com/morluto/rea) 같은 리버스 엔지니어링 도구는 에이전트에게 *"저 앱의 이 기능이 어떻게 돌아가는지 분석해서 내 프로젝트에 똑같이 만들어줘"*라고 시키면 바이너리를 뜯어보고 원래 로직을 그대로 재구현해냅니다.

**에이전틱 공격? 그럼 우리는 에이전틱 방어 — 시간이 갈수록 점점 강해지는 방어입니다.** **ANTI-REA**의 목표는 **REA가 분석할 수 있는 모든 대상과 분석 방식을 결국 전부 막아내는 것**입니다. 내 에이전트에게 **"내 프로그램의 핵심 기능이 REA에게 분석·복제되지 않도록 보호해줘"**라고 자연어로 말하면, 에이전트가 핵심 코드와 주변 단서를 찾아 난독화·가상화(VM)를 걸고, 원래 기능이 깨지지 않았는지와 실행 속도가 기존의 몇 % 수준으로 돌아가는지까지 측정해 알려줍니다.

---

## 사용자의 소프트웨어에서 무엇이 보호되나요?

- **핵심 알고리즘 & 비즈니스 로직**: 프로그램 고유의 핵심 계산식, 독자적인 데이터 처리 흐름, 영업 비밀 알고리즘이 디컴파일되어 외부에 그대로 유출되거나 복제되지 않도록 보호합니다.
- **비밀 데이터 & 암호화 키**: 코드 내부에 포함된 중요 API 키, 라이선스 시그니처, 보안 토큰, 고유 상수 문자열이 평문으로 추출되지 않도록 보호합니다.
- **라이선스 및 권한 인증 검증 흐름**: 유료 라이선스 검증, 사용 기한 체크, 계정 인증 로직이 크래커에 의해 우회되거나 강제로 참/거짓 분기가 변조되지 않도록 지킵니다.
- **프로그램 변조 및 메모리 덤프 방지**: 실행 중인 프로그램의 메모리를 가로채거나(덤프), 디버거 및 후킹 도구(Frida 등)를 붙여 동작을 임의로 조작하고 분석하는 행위를 방어합니다.
- **내부 동작 구조 및 통신 흐름 은닉**: 프로그램이 어떤 내부 함수를 거쳐 동작하고 어떤 시스템 기능을 호출하는지 전체적인 호출 흐름(Call Graph)을 숨겨 분석 단서를 차단합니다.
- **AI 에이전트에 의한 자동 복제(Cloning) 차단**: REA처럼 코드를 읽고 스스로 기능을 복제해내는 자율형 AI 역공학 도구가 내 소프트웨어를 분석하고 카피캣(복제본)을 만들어내는 시도를 차단합니다.

---

## 지원 프로그래밍 언어 (Supported Languages)

ANTI-REA는 네이티브 바이너리부터 가상 머신(JVM, CLR), 스크립트 언어까지 폭넓은 프로그래밍 언어의 핵심 로직을 가상화 및 난독화하여 보호합니다.

| 프로그래밍 언어 | 지원 환경 / 런타임 | 보호 방식 (Engine Route) | 산출 및 배포 형태 |
|:---|:---|:---|:---|
| **C / C++** | Clang / MSVC / LLVM | 순수 Rust 네이티브 다형성 VM (`antirea-rust`) & LLVM 파이프라인 | 독립 실행 파일(EXE) & 네이티브 라이브러리(DLL) |
| **Rust** | `rustc` / Cargo / LLVM | 순수 Rust 네이티브 다형성 VM (`antirea-rust`) & LLVM 파이프라인 | C-ABI 연동 & 네이티브 코어 라이브러리 |
| **Go** | Go 1.20+ (Typed Native) | Native VM + 파사드(Facade) 통합 | 패키지 코어 분리 보호 & 네이티브 바이너리 연동 |
| **Swift** | Swift 5.x+ (LLVM Native) | Swift Native VM + 앱 통합 | 네이티브 앱 코어 & 동적 라이브러리 |
| **C# (.NET)** | .NET 8 / 9 (CLR / IL) | IL Lowering → Native VM 변환 | 관리형 C# 앱 + 네이티브 보호 코어 (P/Invoke) |
| **Java** | OpenJDK 17+ / JVM | JVM 바이트코드 → Native VM | Java 애플리케이션 + JNI 네이티브 코어 |
| **Kotlin** | Kotlin 1.9+ / JVM | JVM 바이트코드 → Native VM | Kotlin 앱 / 서버 서비스 코어 연동 |
| **Python** | Python 3.10 ~ 3.13 | 함수별 평탄화 스택 VM | Pure 모듈 전체 난독화 & Mixed 모듈 번들 |
| **JavaScript** | Node.js / Electron / 브라우저 | 인코딩 가상화 스택 VM | CommonJS 모듈 & 독립 앱 번들 |
| **TypeScript** | TypeScript 5.x+ | TS 트랜스파일 + 인코딩 VM | 빌드 번들 & 코어 모듈 보호 |

> [!TIP]
> 언어별 아키텍처 및 세부 통합 스펙은 [다언어 개발 문서](../../docs/multilanguage-development.md)에서 자세히 확인하실 수 있습니다.

---

## ANTI-REA 진화 로드맵

![ANTI-REA 우주선 로드맵](../assets/defense-roadmap.svg)

- **Phase 1 · 정적 파일 보호 집중 [완료]:** 바이너리의 정적 디컴파일, Ghidra 분석, 수식 복원을 가상화(VM) 및 다계층 바이너리 하드닝으로 원천 저지합니다.
- **Phase 2 · 정적 보호 강화 [완료]:** 함수별 독립 VM/디스패처 분리, 명령어 융합(Fusion), 바이트코드 무결성 체크섬, 심볼 관계 위장으로 정적 분석을 심층 방어합니다.
- **Phase 3 · 자동 공격 테스터 지속 확장 [완료]:** 별도의 자동 공격 AI 에이전트(Tester) 풀을 지속적으로 늘려 매일 실전 공방 테스트를 거치며 스스로 진화하는 방어 루프를 구축합니다.
- **Phase 4 · 동적 보호 강화 및 순수 Rust 엔진 진화 [현재 활성화]**
- **Phase 5 · ? [보안 등급 유지]**
- **Phase 6 · ? [보안 등급 유지]**
- **Phase 7 · ? [미지의 영역 - The Frontier]**

---

## 빠른 시작

### 필수 설치 요구사항 (`Prerequisites`)

- **Rust 툴체인:** `rustc` / `cargo` 1.75+ (`x86_64-pc-windows-msvc` 타겟 — 순수 Rust 방어 워크스페이스 `rust/` 및 생성 런타임 `staticlib` 빌드용)
- **LLVM / Clang & Windows SDK:** `clang` / `llvm-objdump` 및 MSVC 링커(`link.exe`)
- **Python 3.11+:** `antirea.defense_mcp` MCP 서버, 다언어 프론트엔드 및 공격-방어 루프 오케스트레이션용

### 1. 설치 및 에이전트 연결 (`Set up your agent`)

직접 터미널 명령어나 설정 파일을 만질 필요 없이, 사용 중인 에이전트(Claude Code, Cursor, Codex, Gemini CLI 등)에게 아래처럼 시키면 에이전트가 알아서 설치하고 Rust 엔진 빌드 및 MCP 서버 연결까지 수행합니다.

```text
ANTI-REA를 로컬 Python 가상환경(.venv)에 설치하고, 순수 Rust 방어 엔진(cargo build --release --manifest-path rust/Cargo.toml)을 빌드한 뒤, 네가 바로 쓸 수 있게 antirea.defense_mcp 서버를 MCP에 연결해줘.
```

### 2. 에이전트에게 자연어로 시키기 (`Ask your agent`)

설정이 끝나면 복잡한 명령줄 옵션을 외울 필요 없이, 에이전트에게 자연어로 요청하면 됩니다.

```text
내 프로젝트에서 핵심 계산 로직과 주변 단서가 REA에게 분석·복제되지 않도록 보호를 걸어주고, 원래 기능이 깨지지 않았는지랑 실행 속도가 기존의 몇 %로 돌아가는지 알려줘.
```

이미 빌드된 실행 파일과 상용 프로텍터 설정이 있다면 이렇게 요청할 수도 있습니다:

```text
app.exe에 VMProtect로 보호 적용 계획을 먼저 세워서 보여주고, 내가 승인하면 실행해줘.
```

에이전트가 알아서 ANTI-REA MCP 도구를 호출해 연결된 보호 엔진을 점검(`protection_doctor`)하고, 어떤 파일에 어떻게 보호를 걸지 계획을 세워 보여준 뒤(`protection_plan`), 사용자가 승인하면 보호를 적용(`protection_protect`)합니다.

### 3. 터미널에서 직접 쓰기 (`Use the terminal`)

순수 Rust 방어 엔진(`antirea-cli`)을 직접 빌드하고 준비된 LLVM IR 입력에 대해 보호 빌드·4대 검증 게이트를 실행할 수 있습니다:

```powershell
cargo build --release --manifest-path rust/Cargo.toml
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --output-dir <out_dir> --seed 90720261031
```

에이전트를 거치지 않고 터미널에서 직접 지원 엔진 목록과 설정 상태를 확인할 수도 있습니다.

```powershell
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json providers
.\.venv\Scripts\python.exe -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

---

## 어떻게 작동하고, 어떻게 매일 강해지나요?

![ANTI-REA 개요](../assets/antirea-overview.svg)

### 사용자 PC에서의 작동 흐름
에이전트에게 보호를 요청하면 ANTI-REA는 다음 과정을 돕습니다:
- **핵심 함수 너머의 주변 단서까지 탐색:** 핵심 함수 1개만 감춰두면 앞뒤 호출 코드나 상수를 보고 원래 로직을 유추하기 쉽습니다. LLVM 중간 코드(IR)의 호출 관계와 데이터를 따라가며 함께 숨겨야 할 주변 함수를 찾아냅니다.
- **계획 확인 후 안전한 실행:** 에이전트가 임의로 바이너리를 덮어쓰지 못하도록, 입력 파일 해시와 실행 명령어를 먼저 계획(Plan)으로 고정하고 승인된 작업만 실행합니다.
- **기능 보존 및 실행 속도·사용성(Usability) 측정:** VM을 걸면 실행 속도에 오버헤드가 생길 수밖에 없습니다. 보호 후에도 원본과 똑같은 출력을 내는지(`8,489`쌍 × 2회) 검사하고, 로컬 및 실제 공격자 PC에서의 단일 쌍 응답 지연(`~3~4ms`)과 배치 처리량(`usability-telemetry.json`)을 측정해 프로그램이 실사용 가능한지(`USABLE`) 검증합니다.

### 저희가 매일 돌리는 5병렬 실전 공방 루프
저희는 "보호를 걸었으니 안전할 것이다"라고 짐작하지 않고, **방어 전담 환경과 5대 외부 공격자 PC 플릿(REA + Ghidra + 동적 에뮬레이션)을 분리해 매일 실전 공방 루프**를 돌리고 있습니다.

1. **순수 Rust 방어 빌드 및 4대 게이트 검증 (방어 환경):** 자체 구축한 순수 Rust 패스 엔진(`rust/crates/antirea-passes`)으로 새로운 VM·난독화 기법을 입히고, 수천 개의 입출력 일치·PE 상수 은닉·실행 속도/사용성 기준을 통과하는지 검증합니다.
2. **5대 공격자 PC 병렬 블라인드 공격 및 사용성 텔레메트리 수집 (외부 공격 환경):** 소스 코드나 비공개 테스트는 빼고 **보호된 EXE와 기본 입출력 계약**만 5대의 공격자 PC에 전달합니다. 각 공격자 PC는 실제 하드웨어에서 프로그램 실행 속도와 사용성(`usability-telemetry.json`)을 측정하고, REA MCP + Ghidra + Unicorn으로 역공학을 시도하며 노출된 단서(Anchors)와 추론 과정(Inference Steps)을 `reversing-chain.json`에 기록합니다.
3. **`reversing-chain.json` 역이용 및 다음 세대 Rust 엔진 진화:** 공격자 5대가 기록한 정적·동적 앵커(점프 테이블, 내부 호출 그래프, 고정 XOR 슬롯 쌍, 종료 토큰, 스택 초기화 프레임 등)를 분석해 다음 세대 Rust 엔진(`antirea-rust-v4` → `v12`)에서 해당 단서를 원천 제거합니다.

### 케르크호프스의 원칙 (Kerckhoffs's Principle): 오픈소스가 공개되어도 AI 역컴파일러에 뚫리지 않는 이유
ANTI-REA는 오픈소스이므로 공격자(또는 공격자 AI)가 우리의 변환 엔진 소스 코드(`rust/crates/antirea-passes/src/lib.rs`) 전체를 그대로 읽을 수 있습니다. 따라서 현대 암호학의 대원칙인 **케르크호프스의 원칙(알고리즘과 오픈소스 코드가 완전히 공개되어도, 빌드 시드 없이는 원본 로직이나 키를 역산할 수 없어야 함)**을 기반으로 설계되었습니다 (`antirea-rust-v12`):

- **단방향 암호학적 스폰지 CSPRNG (`V12-M1`, 시드 역산 원천 차단):** `SplitMix64`나 LCG 같은 가역적 의사난수 생성기는 바이너리(`.rdata` 또는 `.text`)에서 64비트 상수 1개만 추출해도 역함수로 내부 상태와 `--seed` 전체를 1ms 만에 복원할 수 있습니다. 이를 원천 차단하기 위해 `antirea-passes` (`v12+`)는 **비가역적 512비트(8-워드) ARX 암호학적 스폰지(`KerckhoffsSpongeRng`, ChaCha20/BLAKE3 계열) CSPRNG**와 상태 래칫(Ratcheting)을 적용하여, 오픈소스 코드를 아는 AI가 바이너리의 상수를 모두 추출하더라도 시드나 다른 키를 수학적으로 역산할 수 없게 만듭니다.
- **빌드별 다형성 `VmCtx` 구조체 레이아웃 셔플링 및 전단사 뱅크 순열 (`V12-M2`):** 오픈소스 코드를 읽어도 컴파일된 바이너리 안의 `VmCtx` 필드 오프셋을 알 수 없도록, 매 빌드마다 `#[repr(C)]` `VmCtx` 구조체의 필드 선언 순서와 패딩 배열(`pad_lo`, `pad_hi`) 길이를 Fisher-Yates로 무작위 셔플하고, 64슬롯 헤더(`hdr_ia`/`hdr_ib`)와 1,024슬롯 아레나(`idx_a`/`idx_b`)에 빌드별 고유 전단사 아핀 순열을 적용합니다.
- **다형성 명령어 템플릿 및 슈퍼오퍼레이터 합성 (`V12-M3`):** 오픈소스 변환기의 출력 패턴만 골라내는 맞춤형 역컴파일러(Pattern Deobfuscator)를 무력화하기 위해, 동일한 연산이라도 빌드/분기마다 서로 다른 비선형 MBA·ARX 결합 변형(`poly_sel = 0..3`), 피연산자 평가 순서, 채프 인터리빙을 무작위로 선택합니다.
- **단일 호출 인라인 트랜스크립트 결합 및 다형성 `.rdata` 풀 (`V12-M4`):** `.pdata`에 별도 소형 함수로 노출되던 pre/post 래퍼를 제거하고, `@antirea_score` 내부 인라인 4-qword 스택 트랜스크립트(`%vm.st`)와 단일 호출 `@antirea_dispatch_<tag>` 내부에 엔트리 게이트 및 4-라운드 Feistel 반환 봉인 해제를 통합했으며, `.rdata` 풀 인덱싱(`rpool_mul`, `rpool_add`, `rpool_unmask`)도 빌드마다 다형성 합성합니다.

---

## 지원 엔진

기본 내장된 무료·오픈소스 자체 엔진(**`ANTI-REA Engine`** — 순수 Rust 워크스페이스 `rust/`(`antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`, 현재 `antirea-rust-v12`) 기반 케르크호프스 512비트 단방향 스폰지 CSPRNG, 빌드별 다형성 `VmCtx` 구조체 셔플링, 다형성 명령어 합성, 단일 호출 인라인 트랜스크립트 결합 4-라운드 Feistel 반환 봉인, 무점프테이블 16-클러스터 슈퍼인스트럭션 VM, `u128`+SSE2 `XMM` 상태 결합, `MaybeUninit` 인플레이스 초기화 및 런타임 상수 합성)도 매일 강화되고 있지만, **당장 상용 도구를 함께 쓰고 싶다면 Themida, VMProtect, Code Virtualizer를 연결해 에이전트에게 자연어로 말하기만 하면 됩니다.**

```text
VMProtect(또는 Themida / Code Virtualizer)를 사용해서 실행 속도는 기존의 80% 이상을 유지하면서 핵심 로직은 최대한 강하게 방어해줘.
```

| 엔진 | 연결 방식 | 현재 지원 상태 |
|---|---|---|
| **ANTI-REA Engine** | 자체 순수 Rust 네이티브 보호 워크스페이스 (`rust/`: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`) 및 다언어 VM 파이프라인 | 무료·오픈소스 자체 순수 Rust 엔진(`antirea-rust-v12`). 케르크호프스 단방향 스폰지 CSPRNG, 빌드별 다형성 `VmCtx` 셔플링, 단일 호출 Feistel 반환 봉인, 무점프테이블 클러스터 슈퍼인스트럭션 VM, `u128`+SSE2 `XMM` 상태 결합 및 4대 빌드·사용성 자동 검증 지원 |
| **Themida** | 방어 MCP/CLI (`.tmd`/`.tm` 프로젝트) | 상용 프로텍터 연동 지원 (유료 구매 후 로컬 설치판 연결) |
| **VMProtect** | 방어 MCP/CLI (`.vmp` 프로젝트) | 상용 프로텍터 연동 지원 (유료 구매 후 로컬 설치판 연결) |
| **Code Virtualizer** | 방어 MCP/CLI (`.cv` project) | 상용 프로텍터 연동 지원 (Legacy / v4 지원, 유료 구매 후 로컬 설치판 연결) |

---

## 개발 및 테스트

저장소 루트에서 아래 명령으로 순수 Rust 워크스페이스 단위 테스트와 Python 단위·경계 테스트를 모두 실행할 수 있습니다.

```powershell
cargo test --manifest-path rust/Cargo.toml
python -m unittest discover -s tests -v
```

실제 상용 프로텍터 연동 재현, 새로운 Rust VM 난독화 패스, 일반 프로젝트 빌드 연결, macOS 지원 관련 기여를 환영합니다. 이 프로젝트는 [MIT License](../../LICENSE)로 배포됩니다. (연동하는 각 보호 엔진은 해당 도구의 고유 라이선스를 따르며, 초기 LLVM 패스 픽스처 일부는 MIT 라이선스의 오픈소스 Kagura에서 파생되었습니다.)
