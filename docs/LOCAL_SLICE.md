# 첫 Vertical Slice 로컬 실행 안내

v0.4.0은 [스냅샷·명시적 commit 검사](SNAPSHOT_COMMIT_MODE.md)를 추가했다. 아래 기본 scan은 기존 strict_head 모드다.

Python 3.10 이상과 Git을 사용한다. 아래 명령은 프로젝트 디렉터리에서 실행한다.
핵심 실행기·테스트는 Python 표준 라이브러리만 사용한다. JSON Schema 추가 검사는 별도 개발 의존성을 사용한다.

## 한 번에 실행

```sh
python3 -m govcode_harness demo --output .runtime/first-slice
```

새 합성 저장소에 위험 코드를 커밋하고 검사한다. 예상 판정은 deny다.
같은 합성 저장소에서 알려진 수정본으로 바꿔 두 번째 commit을 만든 후 새 Run으로 재검사한다.
수정본은 지원하는 검사 범위에서 allow이고 증적 저장·검증이 끝나야 통과한다.
명령은 전후 실행 연결과 원문을 남기지 않는 증적을 생성한다.
실행할 때마다 새 출력 경로를 사용한다. 기존 경로를 초기화하거나 덮어쓰지 않는다.

프로젝트 저장소 자체를 커밋하지 않는다. 합성 데모 저장소에만 임시 신원으로 두 개의 커밋을 만든다.
기관 승인이나 법적 준수 판정으로 해석하지 않는다.

## 직접 검사

```sh
python3 -m govcode_harness scan --repo /absolute/path/to/repository --output /absolute/path/to/new-evidence --local-demo
```

검사 출력은 입력 저장소 밖의 새 디렉터리로 지정한다.
기본 검사 대상은 커밋된 HEAD 스냅샷이다. --commit을 명시하면 선택 commit만 검사하고 작업 폴더는 검사하지 않는다. 수정된 작업 파일·비추적 파일·Git ignore 대상 파일도 무시해 통과시키지 않는다.
검사할 저장소는 이런 작업 파일이 없는 엄격한 clean tree여야 한다. 원본 바이트로 직접 비교하고 git status의 clean filter를 실행하지 않는다.
Python 소스가 없거나 미지원 구문·언어·오류가 있으면 통과하지 않는다.
원본 코드는 실행하지 않으며 Findings에 코드 snippet이나 민원값을 넣지 않는다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | allow와 로컬 증적 보관·검증 완료 |
| 2 | 개인정보 로깅 위험으로 deny |
| 3 | 분석 범위 밖이어서 review_required |
| 4 | 입력·구문·파일·보관·검증 오류 |

이 종료 코드를 CI 단계에 연결하면 실패한 검사가 병합·배포를 막도록 구성할 수 있다.
이 프로젝트는 원격 CI·보호 브랜치를 자동 설정하지 않는다.

## 수정 후 재검사

사용자 저장소는 직접 수정·검토한 뒤 새 commit을 만든다. 일반 소스를 자동 재작성하지 않는다.

```sh
python3 -m govcode_harness scan --repo /absolute/path/to/repository --output /absolute/path/to/new-after-evidence --parent /absolute/path/to/before-evidence --local-demo
```

이전 증적의 무결성과 이전 commit의 판정을 확인하고 새 실행을 연결한다.
기존 통과 결과를 새 HEAD의 결과로 재사용하지 않는다.
데모의 수정은 정확히 알려진 합성 코드에만 적용한다.

## 증적 재검증

```sh
python3 -m govcode_harness verify --repo /absolute/path/to/repository --evidence /absolute/path/to/evidence --local-demo
```

현재 HEAD, 정책·도구 digest, 검사 결과, 아티팩트 digest와 receipt를 대조한다.
변조·누락·오래된 HEAD·example provenance는 통과하지 않는다.
로컬 사용자가 증적과 저장소 모두를 다시 작성하는 공격까지 unsigned 해시로 방어할 수는 없다.

## 고정 합성 민원 HTTP API

```sh
python3 -m govcode_harness serve --port 8765 --local-demo
```

loopback 주소에서 고정된 수정 예제를 제공한다. 임의 저장소의 코드를 실행하는 서버가 아니다.
POST /complaints 요청 본문에는 합성 자료만 사용한다. 요청 ID는 서버가 생성한다.
일반 로그에 본문을 남기지 않고 감사 이벤트 호출을 유지한다.
감사 이벤트의 실제 기관 저장·보관·접근 권한은 별도 구현 대상이다.

## 검사 범위와 보관 경계

지원 구문과 미지원 처리의 정확한 범위는 구현·테스트 결과에 맞춰 아래 검증 기록에서 확인한다.
이 검사기는 Python 전체나 전역·언어 간 데이터 흐름을 완전 분석하지 않는다.
미지원 흐름의 검토 필요 판정은 위험이 없다는 뜻이 아니다.

정책은 example_policy이고 기관 승인본이 아니다. --local-demo 또는 demo 명령의 명시적 시험 실행에서만 사용한다.
정책 서명, 기관별 권한·예외, 운영 보관 잠금, 법정 접속기록 관리, 규정 적용성은 후속 범위다.

## 테스트

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
```

추가 계약 검증:

```sh
uv run --no-project --with 'jsonschema>=4.18,<5' python scripts/check_scaffold.py
```

[검증 기록](VALIDATION.md)에 실제 실행 결과와 미검증 범위를 기록한다.

실제 데모 산출물의 JSON 계약 추가 검사:

```sh
uv run --no-project --with 'jsonschema>=4.18,<5' python scripts/check_runtime_contracts.py .runtime/first-slice/before .runtime/first-slice/after
```

## 산출물 구조

데모 디렉터리의 repository/에는 합성 전후 커밋이 있고 before/와 after/에는 각 실행의 증적이 있다.
run.json, decision.json, policy.json, coverage.json, execution.json과 필요시 finding-0001.json을 생성한다.
manifest.json은 메타데이터 파일의 digest 목록, evidence.json은 실행 증적의 식별자와 무결성 정보,
receipt.json은 로컬 저장 완료 기록이다. demo-result.json은 전후 결과와 합성 회귀 확인 요약이다.
민원 본문·원본 로그·코드 원문은 증적 파일에 저장하지 않는다.

운영 증적 보유기간은 설정하지 않았다. 로컬 실행자는 생성 디렉터리를 직접 관리한다.
아티팩트가 삭제되거나 도구·정책이 바뀌면 기존 실행의 검증이 실패할 수 있다.

## 제한과 알려진 신뢰 가정

검사 입력은 UTF-8 Python 소스다. 설정·문서 파일은 inventory에 포함해 변경을 감지하지만 내부 코드를 분석하지 않는다.
정규식 검색을 사용하지 않고 제한된 AST 데이터 흐름을 분석한다. 함수 간·클래스·동적 디스패치·컴프리헨션 등은 검토 필요다.
request_id, operation, result_code, status와 logger·audit 같은 허용 인수는 서버가 만든 비개인정보라는 호출 계약을 신뢰한다. 그 출처를 증명하는 분석은 아니다.
허용된 메타데이터 이름으로 개인정보를 전달해서는 안 된다. 로컬 합성 HTTP API에서는 요청 ID를 서버가 생성한다.

지원 import는 logging과 __future__로 제한한다. 외부 라이브러리·간접 호출·루프·예외 처리·동적 변경을 만나면 검토 필요로 처리한다.

로컬 스냅샷은 파일 100개, 파일당 256,000바이트, 전체 2,000,000바이트로 제한한다.
심볼릭 링크·서브모듈·UTF-8이 아닌 Python 파일은 통과하지 않는다.
Finding의 confidence 0.8은 이 프로토타입의 고정 설명 값이며 보정된 확률이나 측정된 정확도가 아니다. 판정에는 사용하지 않는다.

로컬 Run의 tree_digest는 모든 추적 파일의 경로·내용 SHA-256 목록에 대한 digest이며 Git tree OID와 다르다.
bundle_digest는 이 로컬 예시 정책의 canonical JSON digest다. 서명된 운영 정책·통제·규정 묶음을 나타내지 않는다.
부모 연결은 이전 deny 실행 하나와 새 commit의 직접 연결만 지원한다. 여러 단계의 예외·수정 이력 체인은 후속 범위다.
현재 로컬 증적은 저장소 위치와 부모 증적 디렉터리에 연결된다. 디렉터리를 이동하면 재검증이 실패할 수 있다.
