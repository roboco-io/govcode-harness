# 오철칙 연동 PoC 실행 안내

이번 PoC는 기존 AST 검사에 오철칙 AI-112 민감정보 로깅 프로필을 추가한다.
기본 모드와 달리 별도 Python 3.12 이상 도구 환경이 필요하다. 핵심 실행기의 기본 의존성은 늘리지 않는다.
원래 민원 예제에서 오철칙 단독 검사는 위험을 놓쳤으므로, 기존 검사를 유지하는 선택적 보완 모드다.

## 고정 범위

- 도구: iron-laws 1.11.2.
- 소스: 2a820e8cd7ade4c3060381198ed13bf3e6b43146.
- 검토한 원문: [고정 소스](https://github.com/JinHo-von-Choi/iron-laws/tree/2a820e8cd7ade4c3060381198ed13bf3e6b43146), [보고서 계약](https://github.com/JinHo-von-Choi/iron-laws/blob/2a820e8cd7ade4c3060381198ed13bf3e6b43146/docs/REPORT_FORMATS.md).
- 로컬 예시 정책이다. 기관 승인, 법적 준수, 전체 오철칙 규칙의 적용을 뜻하지 않는다.

## 고정 설치

Python 3.12 이상과 uv의 절대 경로를 지정한다. 도구 소스 아카이브와 잠금 파일의 해시를 확인하고 프로젝트의 .runtime/iron-laws-poc/에만 설치한다.
네트워크는 이 설치 단계에서 사용한다. 기본 검사 명령은 설치 없이도 동작한다.

```sh
python3 scripts/setup_iron_laws.py --python /absolute/path/to/python3.12 --uv /absolute/path/to/uv
```

설치 스크립트 자체도 Python 3.12 이상으로 실행한다. 매번 새 env-고유ID 환경에 한 번만 설치하고 active.json을 원자적으로 전환한다.
이전 환경은 삭제하지 않으며, 변경된 환경의 지문을 자동으로 재등록하지 않는다. 설치 후에는 -B로 캐시 생성을 막고 바이트코드·중복 파일도 지문에 포함한다.

소스 commit·아카이브 해시는 integrations/iron-laws/PIN.json, 실행 의존성 26종은 requirements.lock,
빌드 도구는 build.lock에 고정했다. 시스템이나 전역 Python에는 설치하지 않는다.
이번 설치·실행 검증은 macOS에서 수행했다. 현재 스크립트는 POSIX venv/bin/python 경로를 사용하며 Windows 설치 경로는 후속 작업이다.
재설치·의존성·실행기 변경으로 지문이 달라지면 기존 혼합 증적을 다시 검증하거나 생성해야 한다.

## 혼합 검사

```sh
python3 -m govcode_harness demo --output .runtime/my-iron-demo --with-iron-laws
```

일반 저장소 검사:

```sh
python3 -m govcode_harness scan --repo /absolute/path/to/repository --output /absolute/path/to/new-evidence --local-demo --with-iron-laws
```

검증은 증적에 기록된 외부 검사 모드를 읽고 자동으로 다시 실행한다.

```sh
python3 -m govcode_harness verify --repo /absolute/path/to/repository --evidence /absolute/path/to/evidence --local-demo
```

오철칙을 요청했는데 도구가 없거나 검사 실패·불완전·알 수 없는 형식이면 통과하지 않는다.
기존 검사기의 분석 범위 밖 판정도 외부 통과로 덮어쓰지 않는다.
전후 실행은 같은 검사 모드와 도구·정책을 사용해야 한다.

## 결과와 증적

기존 Run·Finding·Decision·Evidence에 외부 도구 출처와 정제 보고서를 연결한다.
외부 코드 위험과 기존 개인정보 로깅 위험은 별도 예시 정책으로 분리한다.
원본 보고서에는 코드 발췌나 민감한 값이 있을 수 있어 영구 증적에 저장하지 않는다.
보고서 해시는 정제한 결정적 보고서의 해시다. 원본 보고서 전체를 재현했다는 뜻이 아니다.

증적은 계속 unsigned 로컬 데모용이다. 운영 서명·기관 승인·보관 잠금은 추가하지 않는다.
외부 도구·의존성·설정이 바뀌면 기존 혼합 증적을 통과시키지 않는다.

## 기존 합성 corpus 비교

```sh
python3 scripts/compare_iron_laws.py --output .runtime/my-iron-comparison.json
```

기존 양성 25개·음성 24개와 원래 전후 예제를 비교한다.
케이스 ID, 판정, 탐지 여부, 규칙 ID와 집계만 저장하며 코드·민원 원문을 보고서에 넣지 않는다.
이 결과는 합성 표본과 기존 메타데이터 신뢰 계약에 한정된다. 실제 기관 코드의 정확도로 해석하지 않는다.

## 실제 비교 결과와 도입 판단

고정된 실제 도구로 기존 corpus 49건과 원래 전후 예제 2건을 실행했다.

| 항목 | 기존 AST 검사 | 오철칙 AI-112 | 혼합 검사 |
| --- | --- | --- | --- |
| 기존 합성 양성 25건 | 25건 탐지 | 0건 탐지, 25건 allow | 통과한 위험 사례 0건 |
| 기존 합성 음성 24건 | 24건 allow | 24건 allow | 24건 allow |
| 원래 위험 민원 예제 | deny | allow | deny |
| 원래 수정 예제 | allow | allow | allow |

외부 검사 오류·검토 필요는 위 51건에서 0건이었다. 기존 corpus에서 추가 탐지 0건, 음성 지적 0건이다.
이 corpus는 기존 민원 데이터 흐름 검사에 맞춘 합성 표본이다. 오철칙 전체 규칙이나 실제 서비스 전반의 성능으로 일반화하지 않는다.

별도 예제에서 token 인수를 로그에 넘기면 AI-112가 탐지했고, 기존 검사와 외부 검사 두 출처의 Finding을 실제 증적에 남겼다.
이를 메타데이터 로깅으로 수정한 새 commit은 allow였고 부모 실행·정책·도구·보고서까지 재검증했다.
어댑터의 6개 실제 예제는 각 2회 반복해 정제 결과가 같음을 확인했다. whole-request 사례는 검토 필요로 남는다.

**판단: 기본 검사 대체·기본 활성화는 보류한다.** 현재는 식별자·패턴 기반 보완 검사이며, 선택적으로 사용한다.
다음 도입 판단에는 실제 기관 코드와 독립 정답 표본이 필요하다. 이번 결과를 개선율이나 비용 절감 효과로 표현하지 않는다.

기록: [기존 corpus 비교](../integrations/iron-laws/COMPARISON.json), [6개 실제 예제](../integrations/iron-laws/POC_RESULTS.json).

## 검증 결과

기존 104개 시험을 포함한 전체 **146개 통과**. 추가 42개는 어댑터 28개, 통합 14개다.
도구 미설치·출력 상한·시간 초과·형식 오류·불완전 범위·신뢰 지표·REVIEW 지적·설치 지문 변경을 검사했다.
보고서 삭제·변조·프로필 강등·부모 모드 불일치를 거부하고, 원문은 정제된 증적에 남지 않는다.

실제 혼합 데모는 .runtime/verified-iron-laws-final/, 토큰 로깅 전후 검증은 .runtime/verified-iron-token-final/에 있다.
둘 다 위험본 deny·수정본 allow와 로컬 증적 검증을 통과했다. 이 경로는 검증 산출물이며 안내 명령의 my-iron-demo는 사용자가 새로 실행할 수 있게 남겨 뒀다.

이번 PoC는 JSON 보고서 어댑터다. SARIF 업로드, 오철칙 verify-patch 컨테이너 실행, 승인 서명·운영 CI 연결은 추가하지 않았다.
입력 파일명은 어댑터의 ASCII 상대 경로 지원 범위로 제한된다. 미지원 경로는 오류이며 조용히 제외하지 않는다.
원본 보고서의 임시 파일은 처리 후 제거하고, 영구 증적은 허용된 필드만 저장한다.
설치 환경 지문은 로컬 변화 감지 수단이며 공급자 서명이나 악성 코드 부재를 증명하지 않는다.

초기 재설치 환경에 등록되지 않은 중복 파일이 나타나 별도 verify가 거부됐다. 생성 원인은 확정하지 않았다.
검사를 완화하지 않고 새 고유 설치로 전환했으며, 지연 후 별도 프로세스 검사·51개 비교·혼합 데모·별도 verify를 다시 통과했다.
이전 실행과 거부된 PoC 기록은 최종 성공 결과에 포함하지 않는다.
