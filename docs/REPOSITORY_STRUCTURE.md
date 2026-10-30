# 저장소 구조와 변경 경계

## 목적과 리뷰 결과

이 문서는 v0.10.0 이후의 로컬 구조 정리 결과를 설명한다. 목적은 프로젝트 기능의 책임을 모으고 기존 호출을 유지하는 것이다.
실행 코드는 Python 패키지에 있고 apps와 packages는 설계 경계 또는 계약 자료다. 독립 서비스 여러 개가 배포된 구조로 해석하지 않는다.

```text
govcode_harness/
  __main__.py             기존 명령 진입점
  runtime.py·snapshot.py  기존 코드 검사와 공통 Git 입력
  project/
    contracts.py          프로젝트 계약 검증
    profile.py            프로필 버전과 승인
    packs.py              규정 팩 발행·잠금·철회
    applicability.py      적용성 판단
    documents.py          AI 친화적 문서 초안
    cli.py·reference.py   프로젝트 명령과 합성 참조
  contracts/              설치 가능한 JSON Schema 자료
  document_assets/        공통 작성 정책
  ui/                     기존 관리 화면
  project_*.py 등         이전 import의 호환 진입점
tests/                    회귀 시험과 합성 fixture
rule_packs/               공개 가능한 예시 규정 팩
policies/·regulations/    기존 정책·규정 카탈로그
packages/                 초기 설계 경계와 기존 계약 자료
apps/·deploy/             초기 앱·배포 설계 경계
docs/                     명세·ADR·실행 안내·검증·릴리스 기록
scripts/·ci/              준비·검증 도구와 비활성 CI 예시
.runtime/                 로컬 환경·실행 자료. Git과 배포물에서 제외
```

## 호환성과 보안

이전 project_contracts·project_profile·rule_pack·applicability·document_generation·project_cli·rule_pack_reference 모듈은 새 구현과 같은 모듈 객체를 참조한다.
예외 종류·함수·캐시·검증 상태를 복제하지 않는다. 기존 CLI와 JSON·서명 형식은 유지한다.
계약·UI·작성 정책의 자료 경로는 이동하지 않는다. 기존 문서 링크와 설치 패키지의 자료 접근을 보존한다.
검사 도구 digest는 하위 Python 코드·계약·작성 정책을 포함한다. 폴더 이동 뒤 과거 도구 결과를 현재 결과로 재사용하지 않는다.

## R7-E 확장 위치

문서 입력과 산출물 추적 코드는 project/artifact_snapshot.py와 project/delivery_trace.py에 추가했다.
공통 Git 캡처는 기존 snapshot.py에 두고, 코드 분류와 문서 분류는 각각 적용한다.
문서 전용 검사 때문에 코드 검사에서 Python 파일이 없을 때의 오류를 제거하지 않는다.

## 이번에 유지한 경계

기존 코드 검사·서명 증적·관리 화면·모델 수정기의 대규모 이동은 하지 않았다.
tests의 기존 이름과 위치도 유지했다. 기존 검증 근거와 독립 fixture를 구조 정리 과정에서 다시 작성하지 않는다.
모든 기능이 project 패키지로 이동한 것은 아니다. 새 기능의 책임이 확정되면 별도 변경으로 정리한다.

## R7-F~I 확장

project 패키지의 assessment·work_items·document_proposal은 평가와 제한된 수정, stage_gate·control은 현재 단계와 화면/API, evidence는 새 보관 형식, project_reference는 전체 합성 실행을 담당한다.
[전체 실행 안내](PROJECT_REFERENCE_RUNBOOK.md)를 따른다. 이전 루트 모듈의 호환 별칭과 계약·작성 정책 자료 경로는 유지한다.
