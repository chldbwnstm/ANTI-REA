# 선택적 하드닝의 구현 범위와 증거

> Evidence note: raw execution records stay local and are not published with this
> repository. See the [public validation summary](validation-status.md) for the
> verified sample scope and limitations. Local-only record paths below are identifiers,
> not downloadable evidence.

`HARDENING_LAYERS`는 요청에 사용하는 기존 이름 목록이다. 목록에 포함되거나 기본값으로 요청된다는 사실은 해당 보호가 구현·적용·검증됐다는 뜻이 아니다. 현재 모든 이름에 해당하는 보호를 완성한 상태가 아니다.

이 문서는 [hardening.py](../antirea/hardening.py)와 [diversify.py](../antirea/diversify.py)의 자체 생성 경로를 다룬다. 별도 스크립트 VM의 실행기 강화는 아래에서 구분한다. 상용 제품의 기능·설정이나 REA 공격 저항성을 보증하지 않는다. Kagura의 별도 FLA/SUB/CO 패스 증거와 아래 추가 하드닝 증거도 구분해야 한다.

## 별도 Python·JavaScript/TypeScript 실행기 강화

새 pure/mixed-module 빌드는 보호 함수마다 별도 dispatcher 함수와 함수 ID 기반 간접 호출 테이블을 생성한다. 함수별 seed 기반 상태 ID, Python의 XOR 상태 마스킹 또는 JavaScript의 modular-add 상태 마스킹, FETCH/EXECUTE/RETURN 상태 전이 평탄화, handler 그룹 순열을 적용한다. 기존 format-2 함수별 opcode/fetch/operand 인코딩과 현재 명령 단위 디코딩도 유지한다. fetch·operand·연산 보조 함수는 여전히 공유한다.

`runtime_hardening.profile = per_function_flattened_dispatch_v1`의 증거 단계는 `generated_source`다. 함수·테이블·상태·handler 연결을 기록하지만 네이티브 Kagura FLA/SUB/CO 적용이나 JIT 최적화 이후 보존을 뜻하지 않는다. `kagura_passes_applied=false`, `external_resistance=not_evaluated`를 명시한다. 상태 마스크·키·디코더는 로컬 산출물에 존재한다.

phase-23 기록 (local-only record: `../results/2026-10-20/infrastructure/defense-loop/multilanguage-phase23/README.md`)은 6개 공개 빌드 경로의 90,303개 입력 조합과 원본·보호본 각각 2회 관찰(총 361,212회)을 별도로 검증한다. 기능 일치, 실행 비용, 생성 구조, 외부 공격 저항성은 서로 다른 판정이다. 아래 네이티브 선택 기능 8개의 미구현 항목이 이 변경으로 구현된 것은 아니다.

phase-24 앱 연동 기록 (local-only record: `../results/2026-10-21/infrastructure/defense-loop/multilanguage-phase24/README.md`)은 저장된 보호 모듈을 명시적인 Python·JS·TS 앱 파일 목록에 연결하고, 원본·보호본·별도로 복사한 배포본의 CLI 표본 동작을 비교한다. 기존 함수별 스크립트 VM 프로필을 유지한 앱 연동·검증 기능이며 새로운 하드닝 계층은 아니다. 보호 모듈을 제거한 대조군의 실패는 의존성 존재를 확인할 뿐, VM 내부 호출 추적이나 REA 저항성 검증을 대신하지 않는다.

## 현재 구현 범위

| 요청 이름 | 실제 구현 | 주장하지 않는 것 |
| --- | --- | --- |
| `anti_debug` | Windows x86/x64에서 기존 PEB `BeingDebugged` 값을 읽는 조건부 코드. 비정상 값이면 VM 키 계산이 달라질 수 있다. | 일반적인 디버거 차단, Frida·후킹 탐지, 모든 타깃에서의 보존·효과 |
| `anti_tamper` | VM 진입 시 인코딩된 바이트코드 전체와 길이를 검사하는 32비트 체크섬. 알 수 없는 키·길이나 불일치면 `abort()` 경로를 사용한다. | 암호학적 인증, 실행 파일 전체/네이티브 코드의 무결성, 검사 코드 자체의 우회 불가능성 |
| `mba_opaque` | 대수적으로 0이 되는 진단식과 MBA 보조 함수. | 대상 프로그램의 연산 전체를 MBA로 변환했다는 주장. 최적화로 사라질 수 있다. |
| `string_constant_encryption` | 합성된 가드 서명 바이트 배열과 복원 보조 함수. | 사용자 프로그램의 문자열·상수 검색 및 암호화. 다른 경로의 바이트코드 인코딩과도 별개다. |
| `iat_api_hiding` | 심벌 이름을 정수로 바꾸는 해시 보조 함수만 존재한다. | PEB 모듈 순회, export 검색, API 주소 해석, import/IAT 재작성 |
| `multi_vm_indirect_dispatch` | 선택된 VM 함수가 둘 이상일 때 함수별 opcode/fetch/operand 매개변수, 별도 switch dispatcher, volatile 함수 포인터 슬롯을 생성한다. | 암호학적 독립성, 포인터·디코더 은닉, 분석 저항성 향상의 실증 |
| `anti_dump` | 생성 경로에 해당 기능이 없다. | 메모리 덤프 차단, 페이지 보호, 헤더 삭제, 패킹 |
| `anti_llm_honeypot` | 참조되지 않는 IR 함수·데이터와 도달하지 않는 C 분기의 미끼 코드. | LLM에 대한 실증 효과 또는 바이너리 보존. 분석 에이전트에게 지시하는 프롬프트는 넣지 않는다. |

`emit_peb_api_resolver` 같은 기존 함수 이름도 기능 증거가 아니다. 이 함수는 이름과 달리 API를 해석하지 않는다. 단일 함수 또는 multi-VM을 선택하지 않은 경로는 기존 공유·직접 호출 형식을 유지하며 여러 VM으로 집계하지 않는다. 과거 산출물의 구현 상태는 생성 당시 보고서를 따른다.

## API와 선택 규칙

기존 `generate`의 위치 인자 5개는 그대로 유지한다.

```python
generate(input_ir, runtime_source, opcode_source, output_dir, seed,
         *, enabled_layers=None, enable_hardening=True)
```

- `enabled_layers=None`: 기존 이름 8개를 모두 **요청**한다. 미구현 항목도 결과에 공백으로 기록한다.
- `enabled_layers=[]`: 선택적 하드닝을 생성하지 않는다. 기본 VM 다양화·명령 융합·형식 검사는 유지된다.
- `enabled_layers=["anti_tamper"]`: 바이트코드 검사만 선택한다. 미선택 디버거 확인·미끼·API 해시 코드를 자동으로 켜지 않는다.
- `enabled_layers=["anti_tamper", "multi_vm_indirect_dispatch"]`: 둘 이상의 VM 함수가 있으면 함수별 VM과 각 VM의 체크섬을 생성한다. 단일 함수에서는 기존 직접 호출 형식을 유지한다.
- `enable_hardening=False`: 선택적 하드닝을 끈다. 동시에 비어 있지 않은 선택 목록을 주면 오류다.
- 알 수 없는 이름, 문자열 하나를 목록 대신 전달한 경우, 문자열이 아닌 항목은 오류다. 중복 요청은 첫 순서를 유지하며 제거한다.

`parameters`와 `transform_ir`에도 같은 키워드 선택 규칙이 전달된다. CLI는 반복 가능한 `--hardening-layer`와 `--no-hardening`을 제공한다. 생성기는 고정된 Kagura runtime/opcode 소스의 해시를 확인하고, 기존 생성 파일을 덮어쓰지 않는다.

```python
from antirea.diversify import generate
from antirea.hardening import inspect_hardening_artifact

manifest = generate(input_ir, runtime_source, opcode_source, output_dir, seed,
                    enabled_layers=["anti_tamper"])

# 빌더가 실제로 컴파일할 최종 단계 IR을 전달한다.
evidence = inspect_hardening_artifact(
    manifest,
    runtime_after_ir.read_text(encoding="utf-8-sig"),
    core_codegen_ir.read_text(encoding="utf-8-sig"),
)
```

`inspect_hardening_artifact(manifest, runtime_ir, core_ir=None)`는 IR **문자열**을 받는다. 파일을 쓰거나 manifest를 변경하지 않는다. 최적화 후 core IR이 없으면 `None`을 사용한다. 최적화 전 `core.diversified.ll`을 넣고 최종 바이너리에 미끼가 남았다고 해석하면 안 된다.

## 함수별 VM manifest와 적용 확인

multi-VM 경로의 `engine_mode`는 `per_function_indirect`다. 하나의 생성 C 파일 안에 이름 공간이 분리된 여러 런타임을 넣는다. 함수마다 결정적으로 파생한 서로 다른 시드로 opcode 표와 바이트 fetch/operand 피드백 매개변수를 생성하고, 해당 함수의 기존 바이트코드를 다시 인코딩한다. 기존 분기 재배치·명령어 융합·scalar-span 범위 검사는 유지한다. VM 간 호출은 기존 native-call pool을 통해 다른 함수의 wrapper로 들어간다.

| manifest 필드 | 의미 |
| --- | --- |
| `engines[]` | 함수, blob, dispatcher, 슬롯, 체크섬 함수, 매개변수, 사용 handler, codec 해시의 함수별 연결 |
| `dispatcher_symbols` | 보호 패스가 처리해야 할 전체 dispatcher 목록 |
| 최상위 `dispatcher_symbol`, `parameters` | **첫 engine만** 가리키는 호환용 별칭. 전체 VM을 대표하는 값이 아니다. |
| `blobs[].original_sha256`, `original_bytes` | 다양화 전 Kagura 바이트코드의 해시·크기. 새 인코딩의 해시·크기와 구분한다. |
| `independent_vm_parameter_sets` | 생성된 매개변수 집합 수. 이 숫자만으로 최종 보존을 입증하지 않는다. |

`inspect_vm_bindings(core_ir, manifest)`는 함수별 슬롯 초기값, volatile 포인터 로드, 그 값을 이용한 간접 호출, blob 길이·해시와 서로 다른 codec 연결을 검사한다. 네이티브 빌더는 이 결과의 함수 집합이 선택 계획 전체와 일치해야 진행하며, 모든 dispatcher에 FLA/SUB/CO 구조가 남았는지도 각각 검사한다. 공개 경계에서는 모든 dispatcher와 슬롯 참조를 확인한다. 내부 helper도 선택 집합에 포함됐다면 빠짐없이 VM 증거가 필요하다. 지원하지 못하는 선택 함수는 조용히 제외하지 않고 빌드를 실패시킨다.

`inspect_hardening_artifact`는 최종 core IR의 연결과 **모든** runtime dispatcher의 별도 정의가 확인돼야 `per_function_independent_vm_indirect_dispatch`를 retained component로 기록한다. 체크섬 역시 `retained_ir_evidence.engines`에서 각 dispatcher의 자기 검사 함수 호출을 확인하며, 하나라도 확인되지 않으면 전체 `all_engines_checked`가 참이 될 수 없다. 단일 VM의 기존 manifest·직접 호출 경로도 계속 읽을 수 있다.

volatile 슬롯은 컴파일러가 호출을 하나의 직접 호출로 접지 않도록 한 구현 선택이다. 슬롯 초기값·디코더·모든 매개변수는 전달된 바이너리에서 복구할 수 있다. 서로 다른 VM을 생성했다는 사실과 공격자가 더 오래 걸린다는 주장은 별개다. 이 구조 검사는 의미의 완전한 증명이나 적대적으로 위조한 IR의 검증기가 아니다.

## 증거 단계

| 필드/단계 | 확인하는 사실 | 확인하지 못하는 사실 |
| --- | --- | --- |
| `requested_hardening_layers`, `layers.*.requested` | 호출자가 요청한 이름 | 구현·적용 완료 |
| `source_emitted_hardening_layers`, `source_emitted` | 생성 C/IR에서 해당 구성요소가 발견됨 | 최적화 후 보존, 실행 |
| `hardening_capabilities` | 구현 종류, 제한, 생성 소스 해시 | 바이너리 효과 |
| `inspect_hardening_artifact`의 `retained_llvm_ir` | 공급된 IR의 dispatcher·검사 함수·호출·바이트 로드·체크섬 곱셈 등 구조와 IR 해시 | 완전한 제어 흐름/의미 증명, 링크 결과 검증 |
| 빌더의 실행 파일 해시·컴파일 명령 | 조사한 IR을 빌드 산출물에 연결하는 별도 이력 | 기능 동일성·성능·공격 저항성 |
| 별도 기능/성능/외부 공격 평가 | 해당 입력·환경·예산에서 측정한 결과 | 모든 입력·타깃·공격자에 대한 보장 |

호환성을 위해 남긴 `hardening_layers`는 생성 단계에서는 빈 목록이다. `hardening_layers_semantics`에 그 의미를 기록한다. `verified_retained_components` 역시 기능 이름 전체가 아니라 관측한 좁은 구성요소를 담는다. 예를 들어 `encoded_bytecode_length_checksum_check`가 있어도 일반적인 anti-tamper 제품과 동등하다는 뜻이 아니다.

검사기는 보수적인 구조 탐지기다. 컴파일러 표현이 달라 관측하지 못하면 `retention_not_proven`을 기록한다. 이는 기능 부재의 확정이 아니다. IR을 위조하거나 악의적인 주석을 넣는 입력에 대한 보안 검증기로 사용하지 않는다. 신뢰하는 로컬 빌드에서 얻은 IR과 명령 이력을 함께 보관해야 한다.

보조 함수에는 `helper_only_no_application_claim`, 미구현 기능에는 `gap_not_implemented`를 사용한다. `binary_linkage`, `functional_preservation`, `external_resistance`는 이 검사기만으로 검증할 수 없으므로 각각 `not_verified` 또는 `not_evaluated`를 유지한다. 다른 검사에서 얻은 결과를 별도 필드·파일로 연결한다.

## 바이트코드 무결성 검사의 범위

이전 헤더 태그는 기록용이었으며 실제 런타임 검사로 연결되지 않았다. 현재 `anti_tamper` 선택 시 길이의 little-endian 4바이트와 **인코딩된 전체 바이트코드**를 검사한다. 기존 `header_integrity_tag`는 진단용으로 남고 `bytecode_integrity_tag`가 전체 검사에 쓰인다.

런타임은 키와 길이가 등록된 조합인지 먼저 확인한 후 바이트를 읽는다. 같은 VM 안에서 같은 키·길이에 서로 다른 blob을 연결하려 하면 생성 단계에서 중단한다. multi-VM에서는 함수마다 자기 blob을 등록한 별도 검사 함수를 사용한다. 검사 함수는 `noinline`으로 생성하며 해당 dispatcher에서 호출한다. 불일치는 조용히 성공한 결과로 기록하지 않고 `abort()` 경로로 연결한다.

이는 비암호학적 32비트 오류 검출이다. 충돌 가능성이 있고, 예상 태그와 검사 코드가 사용자에게 전달되며 수정될 수 있다. 메모리 주소의 유효성을 일반적으로 증명하지도 않는다. 바이트코드 길이에 비례하는 검사를 VM 진입마다 수행하므로 성능 비용을 별도로 측정해야 한다. 형식 가드 또한 stock VM과의 비호환성 표식이지 암호학적 보호가 아니다.

## 회귀 테스트와 실제 빌드 증거

[test_hardening.py](../tests/test_hardening.py)는 선택 전파, 이름 오류, 전체 바이트·길이 검사, 수학식 일치, 0 키 처리, 과장되지 않는 capability 상태를 검사한다. 로컬 Clang이 있으면 최적화 후 검사 호출의 보존과 미사용 미끼의 제거도 확인한다. Windows에서는 생성한 체크섬 보조 함수만 임시 DLL로 컴파일·실행하여 원본 승인, 80개 위치 각각의 1비트 변경 거부, 다른 길이·키·NULL 거부를 검증한다. 이 테스트는 보호 대상 프로그램이나 공격 도구를 실행하지 않는다.

[test_diversify.py](../tests/test_diversify.py)는 다양화·분기 재배치·융합 회귀와 선택 전달, 모순된 설정, 모호한 무결성 연결의 거부를 검사한다. multi-VM의 재현성·codec 분리, 단일/비활성 경로의 호환성, 슬롯·호출·blob 불일치 거부도 검사한다. 로컬 Clang 검사에서는 실제 최적화된 두 함수 IR의 간접 호출과 각 체크섬 호출을 확인한다.

```powershell
python -m unittest discover -s tests -p test_hardening.py
python -m unittest discover -s tests -p test_diversify.py
```

아래 `.runs` 파일은 저장소에 포함되는 공개 보고서가 아니라 보존된 로컬 증거다. 링크는 해당 산출물이 존재하는 작업 환경에서만 유효하다.

### 이전 공유 VM 산출물

2026-10-20 이전 단계의 로컬 C 산출물 coverage.json (local-only record: `../.runs/native-project-c-final/coverage.json`)은 전체 8개 이름이 요청됐지만 retained component에는 체크섬 검사만 기록한다. 그 산출물의 runtime.after.ll (local-only record: `../.runs/native-project-c-final/runtime.after.ll`)과 protected.codegen.ll (local-only record: `../.runs/native-project-c-final/protected.codegen.ll`)을 근거로, 미끼는 제거됨, anti-debug은 보존 입증 안 됨, IAT 해시는 보조 함수만, **당시** 멀티 VM·anti-dump는 미구현으로 구분했다. fixture-check.json (local-only record: `../.runs/native-project-c-final/fixture-check.json`)의 기능 대조 결과도 당시 산출물에 대한 별도 증거다. 새 구현이 생겼다고 이 과거 보고서나 바이너리를 멀티 VM 적용 산출물로 바꾸지 않는다.

### 새 4함수 multi-VM 산출물

`native-context-multivm-phase4-first`는 Windows x64 합성 C++ fixture의 `context_mix`, `context_prepare`, `context_adjust`, `context_score`에 서로 다른 VM 4개를 적용했다. 공개 `context_public(u32,u32) -> u64`는 검토된 단순 전달 경계로 남았다. coverage.json (local-only record: `../.runs/native-context-multivm-phase4-first/coverage.json`)은 4개 wrapper·slot·blob 연결, 모든 dispatcher의 FLA/SUB/CO 구조와 각 체크섬 호출을 기록한다. 이때 새 retained component는 함수별 VM 간접 디스패치이고, 다른 헬퍼/미구현 상태는 그대로다.

- 독립 기대값 검사 (local-only record: `../.runs/native-context-multivm-phase4-first/fixture-check.json`): 8,192개 난수와 25개 경계 조합, 총 8,217개를 원본·보호 DLL 각각 2회 검사하여 모두 일치했다.
- native_validate (local-only record: `../.runs/native-context-multivm-phase4-first-validation/validation.json`): 별도 8,200개 입력의 출력 일치·결정성을 확인했다.
- 다른 프로필 비용 비교 (local-only record: `../.runs/native-context-multivm-phase4-first-profile-comparison/performance.json`): 동일 worker에서 원본·기존 공유 VM·새 multi-VM을 같은 입력으로 회전 측정했다. 256회 호출, warmup 1회 후 7회 측정의 중앙값은 각각 0.1381ms, 50.9493ms, 29.2183ms였다. 새 DLL은 506,368 bytes로 기존 382,976 bytes보다 약 32.22% 컸다.

이 표본에서 새 프로필의 호출 시간은 이전 공유 VM보다 약 42.65% 낮았지만 측정 원본보다 여전히 약 211.6배 높았다. Python/ctypes 호출·반복 비용은 포함하고 DLL 로드와 프로세스 시작은 제외했다. 짧은 원본 시간의 변동도 있으므로 원시 분포를 함께 봐야 한다. opcode·codec·디스패처 수가 달라졌으므로 동일 프로필 최적화로 취급하지 않으며, 기존 동일 프로필 비교 검사를 완화하지 않았다. 자세한 제한과 해시는 실험 기록 (local-only record: `../.runs/native-context-multivm-phase4-first-profile-comparison/experiment.md`)에 있다.

이는 선택된 정수 ABI fixture의 표본 기능·비용 증거다. 일반 앱 전체, 임의의 내부 helper·언어 기능·부수 효과, macOS 산출물에 대한 multi-VM 호환성을 검증한 것은 아니다. 새로운 REA 공격 평가는 수행하지 않았다.

후속 구현 대조에서 multi-VM 분기 래퍼가 `enable_hardening=False`와 명시적인 비어 있지 않은 선택 목록을 함께 받으면 오류를 내지 않고 목록을 무시하던 회귀를 수정했다. 이제 `parameters`와 동일하게 이름·설정 충돌을 검사하며, 생성 단계 오류에서는 산출물을 쓰지 않는다. 별도 재생성 대조 (local-only record: `../.runs/native-context-multivm-phase4-api-parity/verification.json`)에서 기본 프로필의 core IR, runtime C, manifest는 측정한 기존 산출물과 각각 바이트 단위로 같았다. 이는 설정 검증 수정의 동등성 확인이며 새 기능·성능·공격 평가 결과가 아니다. 과거 빌드의 생성기 해시나 보고서는 덮어쓰지 않았다.

이 변경은 과거 실험 산출물을 다시 평가하거나 덮어쓰지 않는다. 새로운 외부 REA 평가도 포함하지 않는다. “모든 기법 적용”은 아직 달성하지 못했으며, 실제 추가 구현·보존·기능·성능·외부 평가를 각각 통과해야 한다.
