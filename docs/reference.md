# ANTI-REA 명령어 및 검증 레퍼런스 (Reference)

실행 절차는 [실행 가이드](how-to-run.md), 전체 아키텍처와 케르크호프스 화이트박스 설계는 [README.md](../README.md)를 참고하세요.

## 1. 순수 Rust 방어 CLI (`antirea-cli`)

`rust/target/release/antirea-cli.exe`는 다음 명령을 제공합니다:

| 명령 | 주요 인자 | 동작 |
|:---|:---|:---|
| `compile-multilang` | `--workspace <dir> --input-ir <ll> --dispatchers <s1,s2,...> --output-dir <dir> --seed <u64>` | LLVM IR(`.ll`)의 대상 함수들을 순수 Rust `antirea-rust-v12` 다형성 VM 런타임(`antirea_multilang_runtime.lib`)으로 컴파일하고 `rust-multilang-report.json`을 생성합니다. |
| `build` | `--workspace <dir> --input-build <dir> --baseline <exe> --previous <exe> --output-dir <dir> --seed <u64>` | 순수 Rust 다형성 VM 런타임 생성, 네이티브 PE 링크, 4대 자동 검증 게이트(`validation.json`)를 실행합니다. |

## 2. 다언어 브리지 및 MCP 서버 명령

| 명령 | 동작 |
|:---|:---|
| `python -m antirea.rust_multilang --output-dir <dir> --seed <u64>` | 다언어 빌드 스테이지 디렉터리의 LLVM IR을 `antirea-cli compile-multilang`으로 컴파일하고 `protected.rust.dll`을 링크합니다. |
| `python -m antirea.defense_mcp --config <json> providers` | 내장 `ANTI-REA Engine`(`antirea-rust-v12`) 및 연동된 상용 프로텍터(VMProtect, Themida, Code Virtualizer) 목록을 출력합니다. |
| `python -m antirea.defense_mcp --config <json> doctor` | 로컬 프로텍터 경로와 실행 가능 상태를 점검합니다. |
| `python -m antirea.defense_mcp --config <json> plan ...` | 입력 바이너리 해시와 보호 옵션을 고정한 실행 계획(`plan.json`)을 생성합니다. |
| `python -m antirea.defense_mcp --config <json> protect ...` | 승인된 계획(`plan.json`)을 검증한 뒤 보호를 실행합니다. |

## 3. `antirea-rust-v12` 핵심 보호 패스 (`V12-M1` ~ `V12-M5`)

- **`V12-M1` · 단방향 512비트 암호학적 스폰지 CSPRNG (`KerckhoffsSpongeRng`):** ChaCha20/BLAKE3 계열 비가역 ARX 퍼뮤테이션과 상태 래칫으로 키·순열·상수를 파생하여 바이너리 상수 노출 시에도 `--seed` 역산을 원천 차단합니다.
- **`V12-M2` · 빌드별 다형성 `VmCtx` 레이아웃 셔플링 및 전단사 뱅크 순열:** 매 빌드마다 `#[repr(C)]` `VmCtx` 필드 순서, 패딩 배열 길이, 64슬롯 헤더(`hdr_ia`/`hdr_ib`) 및 1,024슬롯 아레나(`idx_a`/`idx_b`) 아핀 순열을 무작위 합성합니다.
- **`V12-M3` · 다형성 명령어 템플릿 및 슈퍼오퍼레이터 합성:** 명령어 암마다 피연산자 평가 순서, 비선형 MBA 항등식(`poly_sel = 0..3`), 디코이 채프 인터리빙을 빌드 시드 기반으로 변형합니다.
- **`V12-M4` · 단일 호출 인라인 트랜스크립트 결합 및 4-라운드 Feistel 반환 봉인:** 호출자 스택의 4-qword 트랜스크립트(`%vm.st`)와 동적 실행 경로를 결합해 반환값을 4-라운드 비선형 Feistel 네트워크로 봉인·해제합니다.
- **`V12-M5` · PE 섹션 상수 위생 및 4대 게이트 자동 검증:** `.rdata`/`.data`/`.text` 섹션 내 평문 상수 잔존 여부를 전수 스캔하고 기준 바이너리와 입출력 동치성을 검증합니다.
