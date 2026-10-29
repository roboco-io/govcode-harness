# v0.10.0 사전 릴리스 검증

기준일은 2026-10-30 KST다. 버전 0.10.0에서 전체 unittest discovery를 다시 실행했다.
**439개 통과, 실패·오류·건너뜀 0개, 131.983초**를 확인했다.
실행 명령은 `.runtime/reference-venv/bin/python -c "from pathlib import Path; exec(Path('.runtime/run-document-suite.py').read_text())"`이며,
검증 대상은 `unittest.defaultTestLoader.discover('tests', pattern='test_*.py', top_level_dir='.')`의 전체 시험이다.

배포용 wheel을 별도 환경에 설치하고 프로젝트 밖에서 `-I -B`로 기본 로깅 데모, 프로필 데모, 팩·적용성 데모와 문서 생성을 실행했다.
로깅 deny→allow와 기능 회귀 3종, 프로필 검증 6종, 팩·적용성 검증 7종을 확인했다.
생성 문서 8개는 AI Doc Ready 0.3.0의 `--fail-on Warning` 구조 검사를 오류·경고·제안 없이 통과했다. 수동 검토 항목은 유지한다.
소스 배포본의 안내·고정 의존성 목록·예시·시험 fixture 포함과 wheel의 계약 스키마·작성 정책 포함을 확인했다.
실행 자료·개인 키를 배포물에서 제외했다. [릴리스 범위](releases/v0.10.0.md)를 따른다.

아래는 각 개발 단계 당시의 역사적 검증 기록이다. 당시 미릴리스·미구현 표시는 해당 단계의 상태이며 현재 릴리스 상태를 대신하지 않는다.

---

# AI 친화적 설계 문서 생성 검증

기준일은 2026-10-30 KST다. 범위는 공통 작성 정책·초안 생성·문서와 검토 메모 분리다.

## 회귀 테스트

`.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py'`와 같은 전체 discovery를 실행했다.
실제 실행은 `.runtime/run-document-suite.py`에서 수행하고 `.runtime/document-suite.json`과 로그에 저장했다.
기존 431개와 신규 8개를 합한 **439개가 통과**했다. 실패·오류·건너뜀은 0개이며 실행 시간은 133.069초다.
신규 검증은 초안과 검토 메모 분리, 수치·날짜 보존, 입력의 구조 지시 방지, 기존 출력 보존, 잘못된 입력 거부,
작성 정책 구분, 문서 digest, 심볼릭 링크·중복 JSON 속성 거부를 포함한다.

## 실제 구조 검사

AI Doc Ready 0.3.0을 `.runtime/aidocready`에 고정 설치했다. 설치 시 패키지 스크립트는 실행하지 않았다.
`aidocready lint .runtime/ai-friendly-design-verified --format json --fail-on Warning --output .runtime/ai-friendly-design-verified-lint.json`을 실행했다.
Markdown 8개에서 오류·경고·제안과 운영 오류는 모두 0개였다. 모든 입력의 coverage.complete는 true이며 수동 검토 항목은 유지했다.
첫 검사에서 작성 정책의 두 번호 목록을 연속되지 않은 번호로 인식한 경고를 확인했다.
순서가 없는 원칙 목록을 불릿으로 수정하고 다시 검사한 결과다.

설치된 패키지를 프로젝트 밖에서 `-I -B`로 실행해 같은 초안을 생성했다.
`.runtime/installed-document-kit`의 Markdown 8개도 같은 옵션의 구조 검사를 통과했다.
초기 review.json의 aidocready_executed=false는 생성 시점의 기록이며, 별도 실행 결과로 자동 변경하지 않았다.

구조 검사 결과는 사실·수치·의미의 검증이나 행안부 공식 인증이 아니다.
HWPX 생성·기관 자료 검증·기존 문서 일괄 변환·R7-E/F 충족 평가는 수행하지 않았다.
[실행 안내](DOCUMENT_GENERATION.md)와 [작성 정책](../govcode_harness/document_assets/DOCUMENT_WRITING_POLICY.md)을 따른다.

---

# v0.9 랄프 참조 구현 최종 검증

## R7-C/D 개발 구현 검증 — 2026-10-29

- 실제 전체 실행: 기존 372개 + 신규 59개 = **431개 통과**, 실패 0·오류 0·건너뜀 0, 93.246초.
- 기존 372개 시험의 소스와 fixture는 이전 R7-A/B 검증 manifest와 같은 바이트임을 확인했다.
- 전체 실행은 unittest discover의 동일 발견 집합을 기존·신규 모듈로 나눠 집계했다. 원본은 `.runtime/r7-cd-full.log`·`.json`에 보존한다.
- 신규 집중 시험: `tests.test_rule_pack`, `tests.test_applicability`, `tests.test_rule_pack_cli`의 59개. 관련 R7-A/B 52개를 합친 집중 실행 111개도 통과했다.
- 발행: 실제 작성·제출·독립 승인·운영자 서명, 불변 버전, 만료·역할·범위·내용 결합·검토·최소 순번 확인.
- 잠금: 현재 승인 프로필과 전체 의존 팩을 고정하고 누락·순환·충돌·다른 내용의 요구·만료·철회를 거부. 동일 요구는 한 번 집계.
- 철회: 키·팩·승인·발행·잠금·검토 digest, 누적 epoch와 보호된 기대 digest, 1시간 참조 신선도 정책 검증. 가짜 높은 epoch와 과거 목록의 재사용을 거부.
- 적용성: typed eq/in/all/any/not, false와 0 구분, 미입력·미확정·not_applicable 주장의 pending 유지, 독립 제외 검토·비예시 근거의 별도 검토, 현재 대상과 다른 검토·중복 event 거부.
- CLI: 규정 팩 정적 검증·실제 서명 데모·원래 증거로 적용성 재판단, 검토 필요 3·검증 오류 4. 적용성 완료는 gate allow가 아님.
- 설치본: 프로젝트 폴더 밖 `-I -B -m govcode_harness project pack-demo`에서 확인 항목 7개 모두 true. 적용/제외/검토 필요가 1/0/2 → 1/1/1 → 2/1/0으로 전이.
- 설치본 결과는 operational_approval=false, requirements_evaluated=false를 유지했다. 실제 검사 어댑터는 실행하지 않았다.
- 정적 문서·기존 계약 검사와 새 예시 팩의 내용·소스 digest 검증은 별도로 수행했다.

실행과 신뢰 기준점은 [R7-C/D 실행 안내](RULE_PACK_APPLICABILITY_RUNBOOK.md), 결정 근거는 [ADR-0014](adr/0014-rule-pack-lock-applicability.md)를 따른다. R7-E 이후의 산출물 검사·충족 평가·단계 게이트·화면은 미구현이며 새 릴리스나 기관 운영 승인을 수행하지 않았다.


## R7-A/B 개발 구현 검증 — 2026-10-29

- 실제 전체 실행: 기존 320개 + 신규 52개 = **372개 통과**, 실패 0·오류 0·건너뜀 0, 84.070초.
- 명령: `.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q`와 같은 발견 집합을 집계 실행했다. 기존 320개 모듈은 변경하지 않았다.
- 신규 집중 실행: `tests.test_project_contracts`, `tests.test_project_profile`, `tests.test_project_cli`의 52개 통과.
- 프로필: 불변 개정·부모 digest·expected_revision 충돌·독립 actor 승인·자기 승인 거부·초안의 기존 승인 보존·만료/철회 후 자동 복귀 금지·시간 역행·기준점 롤백·동시 개정 검증.
- 정보 상태: unknown·missing·not_applicable·known false 구분. 프로필 승인이 정보 미확정이나 요구 적용·충족을 없애지 않음을 확인.
- 공통 계약: 4개 Draft-07 자원과 15종 합성 예시, ID·버전·digest·범위·프로필/검토 대상 결합. 서명·법적 적용 판단과 형태 검증을 구분.
- 일반 패키지 재설치 후 프로젝트 밖 `-I -B` 실행으로 스키마 4개가 소스와 같은 바이트임과 참조 집합 검증을 확인.
- 설치본 `project profile-demo`: 실제 서명과 두 개정, 확인 항목 6개 모두 true, operational_approval=false·requirements_evaluated=false.
- 시스템 Python의 기존 기본 demo도 deny→수정→allow와 응답·감사 보존을 확인.
- 정적 검사: 기존 엔티티 예시 28개·잘못된 계약 8개 거부·로컬 링크 116개 통과. `git diff --check` 통과.

최초 새 환경에서는 선택 도구의 작업 폴더·설치 부재로 기존 시험 일부가 실패하고 3개가 건너뛰어졌다. 고정 소스 SHA-256과 의존성 해시 잠금으로 오철칙 전용 환경을 복원한 뒤 전체를 다시 실행했다. 기존 시험이나 차단 기준은 완화하지 않았다.
원본 초기 기록은 `.runtime/r7-ab-initial.log`·`.json`, 최종 기록은 `.runtime/r7-ab-full.log`·`.json`에 보존한다.
[실행 안내](PROJECT_PROFILE_RUNBOOK.md)와 [ADR-0013](adr/0013-project-profile-contracts.md)을 따른다. R7-C~I는 미구현이며 새 릴리스·기관 운영 승인을 수행하지 않았다.


최종 실행 코드의 전체 회귀: **320개 통과**, 실패·건너뜀0,83.467초. 시작 기준선175개를 보존했다.
실제 참조 CLI는 exit0, 위험본deny·수정본allow·OS격리5검사·관리5검사·보관복구4검사가 모두 통과했다.
실제 모델은 실행하지 않았고 fixture를 명시했다. 운영 승인false·법령 기록pending을 유지했다.

생성 catalog객체13개와 snapshot3개 계약을 확인했다. Run참조문맥의 정확한 선택 필드를 스키마에 추가하고 잘못된 승인/문맥 거부를 별도로 시험했다.
소스·의미·해시가 같은 바이트를 사용하도록 고친 뒤 증적 이동의 실제 서명·digest 검증도 통과했다.

[랄프 완료 보고](RALPH_COMPLETION_REPORT.md),[독립 검토](REVIEW_LEDGER.md),[참조 실행 안내](REFERENCE_RUNBOOK.md),[실제 운영 조건](EXTERNAL_READINESS.md)을 따른다.
아래 기록은 이전 버전의 역사적 검증이며 현재 도구의 통과 결과로 승격하지 않는다.

---

# v0.4.0 R1-A R1-B 검증 기록

기준일: 2026-10-28 KST / 범위: 독립 스냅샷 수집·명시적 commit 모드. R1-C·원격 CI는 미구현이다.

## 최종 회귀

`python3 -m unittest discover -s tests -p 'test_*.py' -q`: 소스 동결 후 **175개 통과**, 실패 0개, 20.160초.
기존 146개를 유지하고 snapshot 16개·commit 모드 13개를 추가했다.

## 실제 실행 확인

- 기본 데모 .runtime/verified-r1-default/: 위험본 deny → 새 수정 commit → allow, 기능 회귀 3종 true.
- 명시적 검사 .runtime/verified-r1-ab/: dirty·staged·미추적·ignore 파일이 있어도 선택 commit만 검사했다.
- 기본 strict 검사는 같은 dirty 저장소를 거부했다.
- 과거 안전 commit의 CLI scan은 allow였고 input_mode=commit_snapshot, worktree_checked=false, head_matches_commit=false를 표시했다.
- 과거 증적의 기본 CLI verify는 STALE_HEAD·exit4로 거부됐다. 같은 --commit SHA를 명시한 verify는 exit0이었다.
- 위험·수정 부모 연결은 같은 commit_snapshot 모드에서 재검증했다.
- 추적 파일 3개 중 Python 1개와 지원 문서 2개를 snapshot.json에 구분했다.
  지원 문서는 코드 검사 통과로 표시하지 않았다. 미검사 작업 파일의 합성 marker는 stdout·증적에 없었다.
- 실제 오철칙 혼합 실행도 과거 commit의 위험본 deny·수정본 allow·명시적 verify exit0을 확인했다.

## 계약과 제한

7개 증적 디렉터리의 catalog 객체 33개와 별도 snapshot.json 7개가 Draft-07 계약을 통과했다.
두 JSON Schema의 메타스키마, 정적 fixture 27개·문서 링크·참조·예시 digest와 잘못된 계약 6종 거부도 확인했다.
Git subprocess의 출력·시간·프로세스 그룹, helper·hook·filter·replace·graft·외부 프로토콜 제한 시험을 포함한다.
심볼릭 링크·gitlink·잘못된 commit·미지원·인코딩·파일 수와 크기 상한, snapshot 삭제·변조·입력 모드 강등·부모 불일치를 거부했다.

이 결과는 선택한 commit의 로컬 검사 결과다. 현재 PR·CI의 예상 commit 대조, 보호 브랜치, 기관 승인·서명은 구현하지 않았다.
원문 없는 manifest가 실제 코드 분석 완료를 뜻하지 않는다. v0.3의 이전 기록을 현재 도구의 통과 결과로 승격하지 않는다.
실행 안내는 [스냅샷과 commit 검사](SNAPSHOT_COMMIT_MODE.md)를 따른다.

아래는 이전 버전의 역사적 검증 기록이다.

---

# v0.3 오철칙 PoC 검증 기록


기준일: 2026-10-28 KST / 외부 도구: iron-laws 1.11.2 / 고정 commit: 2a820e8cd7ade4c3060381198ed13bf3e6b43146

## 최종 회귀 시험

`python3 -m unittest discover -s tests -p 'test_*.py' -q`: 최종 소스 동결 후 **146개 통과**, 실패 0개, 12.746초.
기존 104개 + 어댑터 28개 + 혼합 통합 14개다.
외부 도구 미설치·출력 상한·시간 초과·범위 누락·잘못된 보고서·REVIEW·지문 변경과 증적 강등·변조를 포함한다.

## 실제 도구와 corpus 비교

- 소스 아카이브·실행 의존성 26종·빌드 도구를 해시로 고정하고 프로젝트 내부 환경에 설치했다.
- 기존 양성 25개는 builtin이 25개 탐지했고 AI-112는 0개 탐지했다. 혼합 검사에서 통과한 양성은 0개다.
- 기존 음성 24개는 두 검사 모두 allow다. 외부 오류·검토 필요는 이 corpus와 원래 전후 예제 51건에서 0건이었다.
- 원래 위험본은 builtin deny·외부 allow·혼합 deny였다. 수정본은 모두 allow다.
- 별도 token 인수 로깅은 실제 AI-112가 탐지했다. 두 도구 출처 Finding을 생성하고 새 수정 commit·부모 증적까지 재검증했다.
- 원래 전후·token 전후·whole-request 전후의 6개 예제를 각 2회 반복해 같은 정제 결과를 확인했다.

판단은 **기본 대체·활성화 보류**, 선택적 보완 PoC 유지다. AI-112 한정 합성 결과를 오철칙 전체 성능으로 일반화하지 않는다.
[상세 범위와 실행 방법](IRON_LAWS_POC.md)을 따른다.

## 실제 혼합 실행과 계약

```sh
python3 -m govcode_harness demo --with-iron-laws --output .runtime/verified-iron-laws-final
python3 -m govcode_harness verify --repo .runtime/verified-iron-laws-final/repository --evidence .runtime/verified-iron-laws-final/after --local-demo
```

원래 민원 예제의 혼합 데모는 before deny → 새 수정 commit → after allow, 기능 회귀 확인 3종 true다.
verify는 증적에서 혼합 모드를 읽어 외부 검사까지 재실행한다.
실제 토큰 예제는 .runtime/verified-iron-token-final/에 별도로 보관한다.
두 예제 전후 4개 증적 디렉터리의 **23개 객체**가 catalog의 Draft-07 계약을 통과했다.
정적 fixture 27개·내부 문서 링크 35개·참조·digest 검사와 6개 잘못된 계약 거부도 통과했다.

초기 반복 설치 환경에 등록되지 않은 중복 파일이 추가돼 별도 verify가 지문 변화로 거부됐다. 생성 원인은 미확정이다.
변경된 환경을 다시 등록하거나 중복 파일을 무시하지 않았다. 새 고유 환경에 한 번 설치하고 active.json으로 선택하며 바이트코드·중복까지 검사하도록 수정했다.
캐시 파일 생성을 -B로 막은 뒤 설치·소스를 동결했다. 지연 후 별도 프로세스, 51건 비교, 실제 혼합 데모와 별도 verify를 모두 새로 통과했다. 이전 불완전 실행은 최종 결과에 포함하지 않았다.

독립 검토에서 종료한 부모 프로세스가 파이프를 가진 자식을 남기는 경계 사례를 발견했다.
자체 프로세스 그룹을 종료 상태와 관계없이 정리하도록 수정했고, 해당 회귀의 실패 후 통과와 전체 146개·실제 데모·별도 verify·51건 재비교를 확인했다.

## 유지한 경계

기본 모드는 추가 패키지 없이 실행한다. 선택 모드에만 별도 외부 환경이 필요하다.
원본 코드는 실행하지 않는다. 보고서의 snippet·메시지·값·절대 경로는 정제 보고서에서 제외한다.
새 정책은 로컬 example_policy이며 기관 승인·법적 준수·운영 CI·서명·보관 잠금은 추가하지 않았다.
프로젝트 저장소는 커밋·원격 게시하지 않았다. 아래 v0.2 기록은 이전 단계의 역사적 결과다.

---

# v0.2 로컬 Vertical Slice 이전 검증 기록

기준일: 2026-10-28 KST / 범위: Python 로컬 데모, 제한된 AST 검사, CLI 판정, 합성 API, unsigned 로컬 증적

## 전체 자동 시험

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -q
```

최종 소스 변경 후 **104개 시험 통과, 실패 0개**. 실행 시간 7.244초.
구성은 detector 76개, runtime 25개, API 3개다.
검사기 corpus는 합성 양성 25개·음성 24개이며, 나머지는 오류·경계·회귀 사례다.
전체 Python 프로그램이나 실제 기관 코드에서의 정확도를 측정한 결과는 아니다.

주요 검증: 직접·간접 로깅 전달, 별칭·컨테이너·포맷팅, 미지원 흐름·구문 오류 거부,
새 commit 재검사·부모 실행 연결, 증적 변조·삭제·receipt 누락·stale HEAD 거부,
잘못된 정책·도구·Python 버전 변경·저장 실패 거부, 입력·출력 심볼릭 링크 거부,
작업 파일·비추적 파일·staged index 변경 거부, Git clean filter 미실행, 큰 blob 사전 제한,
원문 본문·코드의 증적 복제 방지, 정규화된 오류 출력.

## 실제 데모와 검증

```sh
python3 -m govcode_harness demo --output .runtime/verified-first-slice
python3 -m govcode_harness verify --repo .runtime/verified-first-slice/repository --evidence .runtime/verified-first-slice/after --local-demo
```

두 명령 모두 종료 코드 0.
합성 위험 commit의 판정은 deny, 수정한 새 commit은 allow.
response_preserved, audit_preserved, body_removed_from_app_log는 모두 true다.
after 증적에서 이전 deny Run의 ID·manifest digest·이전 commit의 조상 관계를 검증했다.
최종 verify는 현재 HEAD·도구·Python·정책으로 판정을 다시 계산하고 receipt까지 확인했다.

사용자가 안내의 첫 명령을 그대로 실행할 수 있도록 .runtime/first-slice 경로는 비워 두었다.
기존 검증 산출물은 .runtime/verified-first-slice/에 있다. 기존 디렉터리 덮어쓰기는 거부한다.

## 실제 loopback HTTP 검사

127.0.0.1의 임시 포트에서 실제 HTTP 서버를 열어 합성 POST /complaints를 보냈다.
202 응답과 서버 생성 32자 요청 ID, 일반 로그의 민원 marker 제외, 감사 이벤트 1건을 확인했다.
잘못된 JSON 요청은 400으로 거부됐다. 외부 서버에는 연결하지 않았다.
HTTP 바인딩이 기본 실행 제한에 막혀 loopback 검증에 필요한 실행 권한을 받아 수행했다.

## JSON 계약과 문서

정적 스캐폴드 검사:

```sh
uv run --no-project --with 'jsonschema>=4.18,<5' python scripts/check_scaffold.py
```

Draft-07 메타스키마·정적 엔티티 예시 26개·참조·로컬 문서 링크 29개·예시 파일 및 manifest digest 확인.
잘못된 계약 6종을 거부했다. 정적 checker는 runtime 디렉터리를 검사 대상에 섞지 않는다.

실제 runtime 계약 검사:

```sh
uv run --no-project --with 'jsonschema>=4.18,<5' python scripts/check_runtime_contracts.py .runtime/verified-first-slice/before .runtime/verified-first-slice/after
```

두 실행의 Run·Decision·Policy·Evidence·Finding **9개 객체**가 기존 Draft-07 catalog와 일치했다.
형태 검증과 실제 의미 검증은 다르다. 의미·소스·판정·무결성·receipt 검증은 verify CLI에서 수행한다.

## 남은 범위와 신뢰 한계

정책은 example_policy이고 draft/disabled다. 명시적 local_demo가 시험 집행을 활성화할 뿐 기관 승인은 없다.
서명·기관 권한·예외 승인·보관 잠금·법정 접속기록 저장·중앙 정책 배포·실제 CI 보호는 미구현이다.
loopback API의 audit는 메모리 카운터이며 법정 접속기록 저장소가 아니다.
unsigned 해시는 작성자 진위·증거능력·공격자의 전체 재작성을 방어하지 못한다.
허용 메타데이터 이름의 비개인정보성은 호출 계약이며 출처를 증명하지 않는다.
규정 적용성은 확정하지 않았고 REG-LOG-008의 시행 유예 원문 대조도 남아 있다.

## 저장소 변경

이 프로젝트에 요청된 코드·테스트·문서만 추가·수정했다.
프로젝트 자체는 아직 커밋·원격 게시·배포하지 않았다.
데모가 만든 별도 합성 저장소에만 위험본과 수정본의 실제 commit 두 개가 있다.
