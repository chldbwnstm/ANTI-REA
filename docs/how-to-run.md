# ANTI-REA 실행 가이드 (How to Run)

Windows x86_64 환경에서 순수 Rust 다형성 방어 엔진(`antirea-rust-v12`)과 `antirea.defense_mcp` MCP/CLI 서버를 빌드하고 핵심 로직을 보호·검증하는 방법을 안내합니다. 세부 옵션은 [명령어 레퍼런스](reference.md), 필수 컴파일러 구성은 [툴체인 설정](toolchain.md)을 참고하세요.

## 1. 에이전트로 한 번에 설치 및 준비하기

필수 도구(Rust 1.75+ `x86_64-pc-windows-msvc`, LLVM/Clang, Visual Studio C++ Build Tools, Python 3.11+)를 직접 설치할 필요 없이, 사용 중인 에이전트(Claude Code, Cursor, Codex, Gemini CLI 등)에게 아래 프롬프트를 전달하면 필수 도구 설치부터 순수 Rust 방어 엔진 빌드 및 MCP 서버 연결까지 자동으로 완료합니다:

```text
필수 도구(Rust 툴체인, LLVM/Clang, MSVC 빌드 도구, Python 3.11+)가 없으면 알아서 설치해주고, ANTI-REA를 로컬 Python 가상환경(.venv)에 설치한 뒤 순수 Rust 방어 엔진(cargo build --release --manifest-path rust/Cargo.toml)을 빌드해서 네가 바로 쓸 수 있게 antirea.defense_mcp 서버를 MCP에 연결해줘.
```

## 2. 순수 Rust 방어 엔진 빌드

저장소 루트에서 순수 Rust 방어 워크스페이스(`rust/`: `antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`)를 릴리스 모드로 빌드합니다:

```powershell
cargo build --release --manifest-path rust/Cargo.toml
```

빌드가 완료되면 `rust/target/release/antirea-cli.exe` 실행 파일이 생성됩니다.

## 3. 다중 언어 및 다중 모듈(`compile-multilang`) 보호 실행

C, C++, Rust, Swift, Go, C#, Java, Kotlin, Python, JavaScript, TypeScript 프론트엔드에서 추출된 LLVM IR(`.ll`)을 `antirea-rust-v12` 다형성 네이티브 VM 정적 라이브러리(`antirea_multilang_runtime.lib`) 및 보호 바이너리로 컴파일합니다:

```powershell
# 1) LLVM IR 모듈(.ll)을 순수 Rust 다형성 VM 런타임(staticlib)으로 컴파일
.\rust\target\release\antirea-cli.exe compile-multilang --workspace . --input-ir <input.ll> --dispatchers <sym1,sym2,...> --output-dir <out_dir> --seed 90720261101

# 2) Python 다언어 브리지를 통한 빌드 및 공유 라이브러리(protected.rust.dll) 링크
python -m antirea.rust_multilang --output-dir <stage_dir> --workspace . --seed 90720261101
```

## 4. 엔드투엔드 보호 빌드 및 4대 검증 게이트 실행 (`build`)

기준 실행 파일(`baseline.exe`) 대비 출력 동치성(`Gate 1`), PE 상수·심볼 은닉(`Gate 2`), 바이너리 변형(`Gate 3`), 원본 무결성(`Gate 4`) 및 응답 속도(`Usability`)를 한 번에 검증하며 보호 실행 파일을 생성합니다:

```powershell
.\rust\target\release\antirea-cli.exe build --workspace . --input-build <ir_dir> --baseline <baseline.exe> --previous <prev.exe> --output-dir <out_dir> --seed 90720261101
```

## 5. Defense MCP / CLI 서버 실행

에이전트(Claude Code, Cursor, Codex, Gemini CLI 등)에서 MCP로 연결하거나 터미널에서 직접 보호 계획(`plan`) 및 보호 적용(`protect`)을 실행할 수 있습니다:

```powershell
python -m antirea.defense_mcp --config .runs/protectors.local.json providers
python -m antirea.defense_mcp --config .runs/protectors.local.json doctor
```

## 6. 단위 및 경계 검증 테스트

```powershell
cargo test --manifest-path rust/Cargo.toml
python -m unittest discover -s tests -v
```
