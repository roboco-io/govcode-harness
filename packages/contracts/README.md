# 데이터 계약

`catalog.schema.json`은 JSON Schema Draft-07의 `$ref`, `definitions`, `oneOf`를 사용한다.
단일 엔티티를 검증하는 entry point는 파일 최상위다. 각 객체에 `kind`를 넣어 구분한다.
기존 catalog의 스키마 검증과 새 프로젝트 계약의 런타임·의미 검증은 구분한다. 새 구현은 아래 R7 계약과 서명 실행 안내를 따른다.
정책 승인·서명·참조·시행 구간·기관 간 권한은 스키마만으로 검증되지 않는다.
세부 의미는 [데이터 모델](../../docs/DATA_MODEL.md)을 따른다.

## R7-A 프로젝트 공통 계약

새 계약의 정본은 [프로필](../../govcode_harness/contracts/project-profile.schema.json), [규정 팩·추적](../../govcode_harness/contracts/rule-pack.schema.json), [평가](../../govcode_harness/contracts/project-evaluation.schema.json), [공통 정의](../../govcode_harness/contracts/project-common.schema.json)다.
설치 패키지에서 동일한 JSON을 읽기 위해 패키지 내부에 배치했다. 기존 catalog.schema.json은 변경하지 않았다.
project_contracts 모듈은 외부 조회 없이 형태·참조·기본 의미를 검증한다. 프로필 외 승인·평가 예시는 실행 권한이나 통과 판정이 아니다.
[예시 집합](../../tests/fixtures/project-compliance/contract-set.example.json)과 [실행·검증 경계](../../docs/PROJECT_PROFILE_RUNBOOK.md)를 참고한다.

R7-C/D의 실제 서명 팩·잠금·철회·적용성 운영 계약도 같은 자원에 포함했다. 단순 shape 검증과 실제 역할·서명·수명·현재 프로필 검증은 구분하며, [실행 안내](../../docs/RULE_PACK_APPLICABILITY_RUNBOOK.md)를 따른다.
