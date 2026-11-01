# 툴체인 설정 및 라이선스 안내 (Toolchain Setup)

설치 및 실행 절차는 [실행 가이드](how-to-run.md)를 따릅니다. ANTI-REA의 순수 Rust 방어 워크스페이스(`rust/`)와 다언어 파이프라인은 아래 툴체인을 기준으로 동작합니다.

| 구성 요소 | 권장 버전 | 용도 |
|:---|:---|:---|
| **Rust (`rustc` / `cargo`)** | 1.75+ (`x86_64-pc-windows-msvc`) | 순수 Rust 방어 엔진(`antirea-ir`, `antirea-passes`, `antirea-validate`, `antirea-cli`) 및 생성 다형성 VM `staticlib` 빌드 |
| **LLVM / Clang** | 18.0 ~ 22.1+ Windows x64 | C/C++/다언어 코어 LLVM IR(`.ll`) 생성, 객체 파일 컴파일 및 `lld-link` / MSVC 링크 |
| **Visual Studio C++ Build Tools** | VS 2022+ 및 Windows 10/11 SDK | Windows x64 PE 실행 파일(`.exe`) 및 동적 라이브러리(`.dll`) 네이티브 링크 |
| **Python** | 3.11+ | `antirea.defense_mcp` MCP 서버, 11개 언어 프론트엔드 변환 및 검증 스크립트 실행 |
| **.NET SDK / JDK / Go / Node.js** | .NET 8/9, JDK 17/21+, Go 1.20+, Node 20+ | C#, Java/Kotlin, Go, JavaScript/TypeScript 다언어 코어 빌드 시 해당 언어 프로젝트에서 사용 |

## 라이선스 및 배포 주의사항

- **ANTI-REA 자체 엔진 및 소스 코드**는 [MIT License](../LICENSE)로 배포됩니다.
- 사용자가 선택적으로 연결하는 외부 상용 프로텍터(Themida, VMProtect, Code Virtualizer) 및 컴파일러 도구(Visual Studio, Windows SDK, LLVM, JDK 등)는 각 도구의 고유 라이선스를 따릅니다.
- 로컬 빌드 캐시(`.runs/`)와 외부 도구 디렉터리(`.tools/`)는 `.gitignore`를 통해 저장소 추적에서 제외됩니다.
