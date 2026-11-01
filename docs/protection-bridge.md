# 방어용 통합 MCP / 상용 보호 어댑터

확인일: 2026-10-19. 현재 단계는 **연결·계획·실행 기록 기반 구현**이다. 실제 상용 보호 도구로 만든 산출물이나 REA 저항성은 아직 검증하지 않았다.

## 구조

```text
사용자의 에이전트
  → ANTI-REA 방어 MCP (stdio, 도구 5개)
    → 공통 Service (설정·계획·확인·작업 기록)
      → Themida CLI
      → VMProtect CLI
      → Code Virtualizer CLI
```

CLI도 같은 Service를 사용한다. 각 제품을 별도 MCP 서버로 만들 필요는 없다. 향후 실제 MCP/API를 제공하는 엔진도 같은 서비스 계약 뒤에 연결할 수 있다.

REA 역시 하나의 MCP 진입점과 공통 워크플로/세션, 도구별 provider를 조합한다. 다만 **모든 도구가 MCP인 것은 아니다**. Hopper·Ghidra는 전용 bridge를 사용하고 IDA는 외부 MCP에 연결한다. 이는 임의의 MCP 서버를 설치·관리하는 범용 관리자와는 다르다. 확인한 upstream은 REA 6.7.0, 커밋 `048d70755ea9ca1d0d159ac78285d62a7ae00b21`이다. [REA 구성 코드](https://github.com/morluto/rea/blob/048d70755ea9ca1d0d159ac78285d62a7ae00b21/src/composition/binary.ts), [아키텍처](https://github.com/morluto/rea/blob/048d70755ea9ca1d0d159ac78285d62a7ae00b21/docs/architecture.mermaid), [IDA 연결](https://github.com/morluto/rea/blob/048d70755ea9ca1d0d159ac78285d62a7ae00b21/docs/ida-provider.md).

새 모듈은 `antirea.defense_mcp`와 `antirea.protectors`다. 과거 공격 평가용 `antirea.bridge`를 가져오거나 실행하지 않는다. 상용 제품의 공식 MCP가 존재한다고 가정하지 않고, 문서화된 네이티브 CLI에 연결한다.

## 제품별 계약과 한계

| Provider | 실행 파일 / 프로젝트 | 문서화된 호출 | 이번 구현 범위 |
|---|---|---|---|
| `themida` | `Themida.exe`, `.tmd` 또는 내보낸 `.tm` | `/protect PROJECT /inputfile INPUT /outputfile OUTPUT /shareconsole` | Windows 호스트, x86/x64 PE 입력 |
| `vmprotect` | `VMProtect_Con.exe`, `.vmp` | `INPUT OUTPUT -pf PROJECT` | Windows 호스트, x86/x64 PE 입력. Lite는 콘솔 경로 차단 |
| `code_virtualizer` | `Virtualizer.exe`, `.cv` | `/protect PROJECT /inputfile INPUT /outputfile OUTPUT /shareconsole` | Windows 호스트, x86/x64 PE 입력. 1–3 계열 legacy / 4 계열 프로필 구분 |

명령 근거: [Themida CLI](https://www.oreans.com/help/tm/hm_protecting-through-the-command.htm), [VMProtect 공식 설명서](https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/), [Code Virtualizer 4 CLI](https://www.oreans.com/help/cv4/protecting-an-application/protecting-through-the-command.html), [구버전 Code Virtualizer CLI](https://www.oreans.com/help/cv/hm_protecting-through-the-command.htm).

- 사용자가 제품 GUI에서 생성·검토한 프로젝트를 입력한다. 핵심 함수 선정, SDK 마커 삽입, vendor 프로젝트 생성·수정의 자동화는 이번 범위가 아니다. Code Virtualizer는 EXE가 있다는 사실만으로 모든 코드를 가상화하지 않는다. 선택 영역/마커 등 실제 적용 범위를 별도로 확인해야 한다.
- Code Virtualizer 4의 macOS 대상 지원과 **macOS에서 보호 도구를 네이티브 실행하는 것**은 다르다. 공식 FAQ는 보호 도구 자체가 Windows에서 실행된다고 설명한다. 이번 어댑터에는 Mach-O·ELF·ARM64 또는 Mac 실행 경로가 없다. [호스트/대상 FAQ](https://www.oreans.com/help/cv4/faq/general/i-can-see-that-latest-code-vir.html).
- 최신 Themida의 실행 파일은 사용자가 명시한다. 대상 CPU만으로 `Themida64.exe`를 추측하지 않는다. [공식 변경 기록](https://www.oreans.com/ThemidaAllWhatsNew.php).
- Themida/Code Virtualizer 데모는 VM 강도·일부 기능이 제한된다. 데모의 CLI 동작과 다른 PC에서의 산출물 실행 가능성은 실제 설치판으로 확인해야 한다. 어댑터는 trial 결과를 표시하지만 정식판 성능으로 일반화하지 않는다. VMProtect Lite에는 콘솔 버전이 없으므로 차단한다. [Oreans 데모 제한](https://www.oreans.com/downloads.php), [VMProtect 설명서](https://vmpsoft.com/vmprotect/user-manual/working-with-vmprotect/).
- 도구·SDK·라이선스 키는 재배포하지 않는다. 사용자가 자신의 프로그램에 대해 적법한 라이선스/평가 조건으로 사용하는 방식이다. `license_acknowledged`는 사용자 확인값이지 라이선스의 유효성 검증이나 사용권 확대가 아니다. [Themida 사용권 FAQ](https://oreans.com/help/tm/hm_faq_i-bought-a-themida-license-to-.htm), [Code Virtualizer 사용권 FAQ](https://www.oreans.com/help/cv4/faq/sales/what-is-the-difference-between.html).

## 설정

설정 파일은 소유한 workspace 내부에 둔다. 이 머신에는 `.runs/protectors.local.json`을 **빈 provider 목록**으로 만들었으며, 실행 가능한 상용 도구는 등록하지 않았다. [설정 예시](protection-config.example.json)는 경로를 교체해야 하는 템플릿이다. `.runs/`는 gitignore 대상이다.

모든 경로는 절대 경로다. 필요한 provider만 등록해도 된다. `workspace_root`는 기존 폴더여야 하며 출력 위치는 항상 `<workspace>/.runs/protection-jobs`다. 임의 명령·추가 CLI 인자·셸 설정은 받지 않는다.

실제 실행을 허용하려면 다음을 사용자가 확인한다.

1. 자신의 정식판 또는 허용된 평가판 경로, 버전, 에디션, CLI 프로필을 등록한다. 버전/에디션은 사용자 선언이며 자동 검증된 정보가 아니다.
2. GUI에서 보호 프로젝트를 검토한다. 스크립트·플러그인·외부 파일 참조도 확인한다. 프로젝트는 소유한 workspace 안에 둔다. 상대 경로 의존성은 제품별로 시험해야 하며 가능하면 명시적인 절대 경로를 사용한다.
3. `Get-FileHash -Algorithm SHA256 -LiteralPath '절대 경로'`로 실행 파일과 프로젝트를 확인한다. 실행 파일에는 `sha256`, 프로젝트는 `approved_projects`의 `{"path":"절대 경로","sha256":"소문자 64자리 해시"}`로 등록한다.
4. 조건을 확인한 뒤 `license_acknowledged: true`, `allow_execution: true`로 변경한다. API 키나 라이선스 키 자체는 설정에 쓰지 않는다.
5. MCP 서버를 재시작하고 doctor/plan을 실행한다. 계획의 경로·명령·해시·blockers를 검토한 뒤 그 계획의 fingerprint로 실행을 요청한다. 계획 후 설정/입력/도구/프로젝트가 바뀌면 새 계획이 필요하다.

에디션 값은 `trial`, `lite`, `professional`, `ultimate`, `licensed`, `unknown`이다. 이는 공통 메타데이터이며 각 제품에 모두 해당 에디션이 있다는 뜻은 아니다. `unknown` 에디션은 실행을 차단한다. Code Virtualizer는 선언된 major 버전과 CLI 프로필이 맞아야 한다.

## CLI와 MCP

아래는 PowerShell에서 저장소 루트를 작업 디렉터리로 사용하는 예다. 도구 경로가 없어도 providers/doctor 조회는 가능하며 제품 실행은 하지 않는다.

```powershell
$protectorConfig = (Resolve-Path .runs/protectors.local.json).Path
python -m antirea.defense_mcp --config $protectorConfig providers
python -m antirea.defense_mcp --config $protectorConfig doctor
```

도구·프로젝트를 등록한 후:

```powershell
python -m antirea.defense_mcp --config $protectorConfig plan --provider themida --input 'C:/path/to/ANTI-REA/build/app.exe' --project 'C:/path/to/ANTI-REA/protection/app.tmd' --timeout-seconds 600
python -m antirea.defense_mcp --config $protectorConfig protect --plan-id '위에서 반환한 plan_id' --fingerprint '위에서 반환한 fingerprint'
python -m antirea.defense_mcp --config $protectorConfig job --job-id '위에서 반환한 job_id'
python -m antirea.defense_mcp --config $protectorConfig serve
```

패키지 설치 시 `anti-rea-defense` 진입점도 같은 CLI를 제공한다. 에이전트 클라이언트에는 stdio 서버 하나를 연결한다. 예시의 Python 경로는 이 저장소 패키지가 설치된 환경으로 바꿔야 한다. 아직 사용자 전역 에이전트 설정은 변경하지 않았다.

```json
{
  "mcpServers": {
    "anti-rea-defense": {
      "command": "C:/path/to/venv/Scripts/python.exe",
      "args": ["-m", "antirea.defense_mcp", "--config", "C:/path/to/ANTI-REA/.runs/protectors.local.json", "serve"]
    }
  }
}
```

노출 도구는 `protection_providers`, `protection_doctor`, `protection_plan`, `protection_protect`, `protection_job` 다섯 개다. 임의 셸, 공격, 대상 실행, 배포 도구는 없다. MCP는 초기화 후 도구 호출을 받고, 실행형 알림(notification)은 무시한다. UTF-8 줄 단위 JSON-RPC이며 표준 출력은 프로토콜 전용이다. [MCP stdio 규약](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

이번 서버는 **동기 실행**이다. 실행 시간은 기본 600초, 최대 3,600초이며 긴 작업은 클라이언트 timeout을 맞추거나 같은 CLI로 실행해야 한다. 비동기 작업 큐·MCP cancel 기능을 구현했다고 주장하지 않는다. 기존 `.runs/defense-loop/STOP`이 있으면 실행을 차단하고 실행 중에도 확인한다.

## 안전 경계와 기록

- 수신 보고서(`rea-analysis-reports/`)와 격리된 inbox 안의 입력·프로젝트·설정·실행 파일을 거부한다. 링크·reparse point·하드링크·NTFS alternate stream도 거부한다. 이는 알려진 경로/실수 방지 경계이지 파일의 출처를 증명하거나 동일 사용자 권한의 적대 프로세스를 막는 OS 샌드박스가 아니다.
- 계획은 명령과 파일 해시를 포함한 fingerprint로 확인한다. 실행은 명시적으로 허용된 설정과 고정된 도구/프로젝트 해시를 요구한다. 원본은 작업 폴더로 복사하고 별도 출력 경로를 강제한다. 한 번 시도한 job은 재실행하지 않는다.
- 승인한 프로젝트는 **신뢰하는 네이티브 입력**이다. 제품은 스크립트·플러그인을 실행하거나 다른 파일/네트워크에 접근할 수 있다. 프로젝트 해시 하나가 외부 참조 파일·DLL까지 고정하지 않는다. 공급망 신뢰나 적대적인 프로젝트 격리가 필요하면 별도의 VM/OS 권한 경계가 필요하다.
- 제품 실행은 shell 없이 숨김 시작하며, 소유 프로세스 트리를 timeout/STOP/종료 시 정리한다. 제품이 이후 GUI 창을 띄우는 것까지 막는 것은 아니다. 원본 입력·프로젝트·도구가 실행 중 바뀌면 실패로 기록한다.
- 기존 vendor 로그를 덮어쓰지 않고 독점 생성한다. 동일 workspace의 같은 provider는 한 번에 한 작업만 실행한다. 부모 종료·할당된 Windows Job의 빈 상태·핸들 정리를 모두 확인하지 못하면 `cleanup_unverified`로 처리하고 provider를 보류한다. Job 할당 직전에 생성된 자식까지 완전히 격리한다는 보장은 아니다.
- 실행 전 `.runs/protection-jobs/.locks/<provider>.quarantine.json`을 기록하므로 실행기 자체가 비정상 종료돼도 다음 작업이 자동 시작되지 않는다. doctor의 `provider_quarantined_operator_inspection_required`는 운영자 점검이 필요하다는 뜻이다. 해당 작업 로그/PID, 남은 소유 프로세스, 프로젝트/원본 무결성을 확인하고 기록한 후에만 운영자가 정확한 marker 하나를 수동 해제한다. 전체 작업 폴더 삭제나 자동 재시도/자동 해제는 하지 않는다. 정상 정리를 증명한 현재 작업만 marker를 `cleared`로 바꾼다.
- 각 계획/실행은 `.runs/protection-jobs/<job-id>/plan.json`, `job.json`, `README.md`를 남긴다. 실행 시 vendor stdout/stderr와 process 기록이 추가된다. 이 폴더에는 비공개 경로·프로젝트 정보가 있으므로 공격자에게 공유하지 않는다.

## 판정과 다음 단계

최대 성공 상태는 `artifact_created_unvalidated`다. 이는 종료 코드 0과 출력 PE의 기본 형식/아키텍처 확인을 뜻한다. 정상 기능, 실제 VM 적용 범위, 서명/배포 적합성, 실행 성능, REA 저항성은 모두 별도다. PE 확인은 완전한 파일 검증이나 언어 호환성 판정이 아니다.

실도구 연동 시험 → 엔진별 적용 범위 증거 → 원본 대비 기능/성능 → 검토된 공개 산출물 → 외부 공격 평가 순으로 확장한다. 기존 `defense_validate`의 ANTI-REA Native 전용 증거 검사를 상용 엔진에 통과한 것처럼 재사용하지 않는다. 아직 보호 프로젝트 생성, 엔진별 적용 증명과 외부 평가 루프 연결은 구현하지 않았으며, 현재 공유 중인 `app.exe`를 이 기능이 자동 교체하지 않는다.
