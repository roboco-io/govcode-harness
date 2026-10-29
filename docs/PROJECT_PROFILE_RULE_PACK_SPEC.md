# R7 프로젝트 프로필·규정 팩 상세 명세 초안

기준일: 2026-10-29 / 상태: v0.10.0의 R7-A~D 로컬 참조 구현·R7-E~I 설계
[구현 계획](plans/2026-10-29-project-profile-rule-packs.review.md)과 함께 검토한다.
사용자 선택은 사업 산출물·요구사항 추적이다. [제품 목적](PRODUCT_DIRECTION.md)을 유지하며 개인정보 로깅을 첫 사례로 연결한다.

## 1. 현재 구현에서 재사용할 것과 새로 만들 것

| 현재 코드 | 재사용할 기반 | 새로 필요한 것·호환성 경계 |
| --- | --- | --- |
| snapshot.py | 안전한 Git 호출·commit 검증·전체 파일 목록·용량 제한 | 문서 원문을 같은 바이트로 읽는 ProjectSnapshot. 현재 문서는 supporting_file이며 내용 검사 대상이 아님 |
| runtime.py·gate.py | 기존 로깅 판정·현재 commit 대조 | 새 평가에서 검증된 기존 결과를 참조. 기존 allow의 의미와 CLI 기본 동작 유지 |
| security.py·governance.py | 정규화·Ed25519·역할·독립 승인·철회 원칙 | RulePack과 프로필의 별도 검증·승인 기록. PolicyBundle에 새 필드를 몰래 추가하지 않음 |
| evidence_snapshot.py·archive.py | 같은 캡처 바이트의 검증·서명 증적 투영 | 프로필·팩·추적·검토의 새 원문 없는 투영과 새 기록 유형 |
| evidence_store.py | 범위별 접근·보관 잠금·백업 복구 | 새 평가 유형 저장과 승인·원문 접근의 분리. 기존 보관기의 검증 콜백·허용 형식을 새 검증기와 명시적으로 연결 |
| control_plane.py·ui | author·approver·operator·auditor, 기관·프로젝트 경계 | 프로필·요구·작업·충족 현황 화면과 서버 측 권한 검사 |
| patching.py | 승인·대상 결합·원본 보존 원칙 | 기존 수정기는 제한된 Python 전용. 문서 초안과 적용기를 별도로 설계 |

기존 코드 수집기는 Python이 없으면 NO_SUPPORTED_SOURCE를 남긴다. 문서 검사를 위해 이 차단 조건을 전역으로 제거하지 않는다.
문서 전용 단계는 별도 입력 유형으로 선언한다. 코드 검사가 필요한 프로젝트에서 Python 파일을 삭제하거나 프로필을 미확정으로 바꿔 코드 게이트를 우회할 수 없어야 한다.
현재 CI의 코드 필수 검사는 독립적으로 유지하며 새 단계 게이트를 추가한다.
의존성은 기존 Python 표준 라이브러리와 참조 환경의 cryptography·jsonschema를 우선 사용한다. 규정 팩별 자동 패키지 설치나 새 모델 런타임은 도입하지 않는다.

## 2. 최소 객체 계약

R7-A 공통 계약과 R7-B 프로필, R7-C 팩 발행·잠금, R7-D 적용성을 구현했다. 실제 데이터·명령과 신뢰 기준점은 [R7-C/D 실행 안내](RULE_PACK_APPLICABILITY_RUNBOOK.md)를 따른다. 객체의 형태·참조 검증과 서명·권한 검증은 구분한다. 현재 catalog.schema.json의 객체·enum은 변경하지 않았다.
새 Draft-07 스키마를 분리하고 기존 Run·Decision과는 명시적 참조로 연결한다.
모든 식별자는 기관·프로젝트 범위를 갖고, 각 버전은 불변이며, 서명 검증에는 서버가 가진 신뢰 목록을 사용한다.

| 객체 | 최소 필드 | 필수 제약 |
| --- | --- | --- |
| ProjectProfile | id, revision, tenant_id, project_id, jurisdiction, project_type, stage, facts, source_refs, owner_ref, lifecycle | facts의 값과 확인·미확정 상태를 분리. 개인정보 값·계약 원문은 제외 |
| ProfileApproval | profile_digest, reviewer_ref, decision, reason_ref, reviewed_at, expires_at | 작성자와 승인자 분리. 현재 프로필과 정확히 일치 |
| RulePackManifest | pack_id, version, schema_version, domain, source_refs, requirement_refs, task_templates, check_specs, dependencies, not_before, expires_at | 실행 코드·shell·동적 다운로드·임의 모델 프롬프트 금지. 참조하는 전체 내용 digest 포함 |
| RequirementSpec | id, version, source_category, source_verification, normativity, basis_kind, applicability_expr, stages, required_artifacts, check_refs, review_required | 출처 유형·확인 상태·강제성을 분리. 제목만 있는 법령은 확정 의무가 아님 |
| PackApproval | manifest_digest, author_ref, approver_ref, decision, scope, validity | 독립 승인·서명·철회 확인. 출처 검토와 팩 발행 승인은 별도 |
| ProjectPackLock | profile_digest, pack_refs, pack_digests, policy_bundle_refs, selection_review_ref, sequence, validity | 자동 latest 선택 금지. 의존성·순환·충돌·최소 순번 검증 |
| ApplicabilityDecision | requirement_ref, profile_digest, pack_digest, result, reason_codes, fact_refs, reviewer_ref | applicable / not_applicable / pending. 제외에는 근거·승인 필요 |
| ArtifactRef·TraceLink | artifact_id, kind, relative_path, content_digest; from_ref, to_ref, relation | 요구·설계·시험 계획·시험 결과·검토를 구분. 다른 프로젝트·없는 ID·중복 ID 거부 |
| ReviewDecision | requirement_ref, artifact_digests, subject_digest, reviewer_ref, decision, reason_ref, validity | 문서 안의 ‘승인’ 문구를 신뢰하지 않음. 독립 서명 기록만 승인으로 인정 |
| WorkItem | requirement_ref, action_type, owner_ref, stage, expected_artifacts, blockers, status | 무슨 자료·작업·검토가 필요한지 설명. AI가 완료 상태를 임의 확정하지 않음 |
| RequirementAssessment | requirement_ref, applicability_ref, check_results, review_refs, status, reason_codes | 자동 검사·담당자 검토·미실행·기한 전 상태를 분리 |
| ProjectEvaluation | evaluation_id, subject_digest, commit_sha, profile_digest, lock_digest, artifact_manifest_digest, tool_digest, review_set_digest, assessments, parent_ref | 새 입력마다 새 평가. 과거 이력은 보존하고 현재 화면에서 stale로 표시 |
| ProjectStageReceipt | evaluation_digest, stage, outcome, reason_codes, required_check_refs, evidence_receipt_ref | 해당 단계·입력의 결과. 현재 코드 게이트와 프로젝트 전체 준수를 대체하지 않음 |

### 분류와 기존 계약의 관계

- source_category는 법령·행정규칙·기관 규정·계약상 기준·권고 가이드·예시를 구분한다.
- source_verification은 원문·버전·조항 확인 상태다. 프로젝트 적용성·승인과 다른 필드다.
- normativity는 mandatory / recommended / example / undetermined다. 권고를 필수로 선택하면 기관·계약상 선택 근거를 별도로 기록한다.
- 기존 basis_kind의 네 종류는 그대로 보존한다. 계약·권고를 statutory_obligation 또는 institutional_policy로 억지 변환하지 않는다.
- 새 요구 분류는 새 팩 계약에서 처리한다. 기존 정책 연결 어댑터는 기존에 검증 가능한 분류만 받는다.
- 초기 합성 팩은 basis_kind=example_policy, context=synthetic_reference, operational_approval=false다. 미확정 법령을 끼워 넣어 집행하지 않는다.

## 3. 프로필과 적용성

프로필의 기본 조건은 관할 KR, 프로젝트 종류, 현재 단계, 개발·문서 입력 유형, 기관·계약 기준 참조, 시스템 특성, 담당자다.
사업 규모·기관 유형 등은 해당 팩에서 필요한 경우에만 구조화한 값과 출처를 받는다. 실제 기관 분류를 추정해 채우지 않는다.
미입력·명시적 false·해당 없음은 서로 다르다. unknown 값에는 확인할 담당자와 다음 작업을 연결한다.

| 조건 계산 | 결과 |
| --- | --- |
| 확인된 사실이 조건을 만족 | 적용 후보. 출처·프로필·팩의 필요한 승인을 확인한 뒤 applicable |
| 확인된 사실이 조건을 만족하지 않음 | 제외 후보. 근거·독립 승인 전에는 pending |
| 사실 미확정·범위 판단 미완료 | pending 및 검토 작업. 자동 false 또는 제외로 바꾸지 않음 |
| 지원하지 않는 연산자·필드·타입·잘못된 날짜 | error. 조건을 무시하거나 AI 추론으로 보완하지 않음 |

초기 조건 언어는 typed eq / in / all / any / not만 허용한다. unknown은 3값 논리로 계산하며 not unknown도 unknown이다.
표현식의 중첩·항목 수에 제한을 두고 eval·정규식 실행·외부 URL 조회를 허용하지 않는다.
프로필 단계는 initiation / requirements / design / implementation / verification / acceptance / operations로 제안한다. 팩은 지원하는 단계만 선언한다.
프로필 개정은 새 revision과 재승인을 만든다. 미완성 개정본을 활성 승인본 위에 덮어쓰지 않는다. 저장 시 expected_revision을 대조하고 동시 변경은 충돌로 반환한다.

## 4. 규정 팩의 발행과 잠금

팩은 초안 → 제출 → 독립 승인 → 발행 → 만료·철회의 이력을 갖는다. 발행 시 기존 author·approver·operator 역할을 사용한다.
권한 검사는 역할 이름만 아니라 기관·프로젝트·대상 객체까지 대조한다. 작성자가 다른 키를 만들어 자기 승인할 수 없어야 한다.

ProjectPackLock에는 고정된 팩 버전과 digest, 승인·출처 참조, 프로필 digest, 유효 구간, 순번을 넣는다.
공유 요구는 같은 정규 ID·버전·내용일 때만 한 번 집계한다. 같은 ID에 다른 내용이 있으면 충돌 오류이며 임의 우선순위로 덮어쓰지 않는다.
팩 의존성 누락·순환·서명 오류·범위 불일치·만료·철회·순번 역행은 error다. 네트워크 장애를 무기한 캐시 허용으로 바꾸지 않는다.
서명 대상은 종류·계약 버전·기관·프로젝트·내용 digest를 포함한다. 유효한 정책 서명을 팩 승인이나 검토 승인으로 바꿔 쓸 수 없어야 한다.

검사 명세는 설치·승인한 adapter_id와 허용된 구조화 매개변수만 참조한다.
팩 안의 shell, Python 코드, 웹훅, 임의 실행 파일·패키지 설치 경로를 실행하지 않는다.
팩의 수정 제안은 새 버전이다. 발행된 팩의 요구를 지워 충족률을 높이지 않는다.

## 5. 첫 추가 Vertical Slice: 사업 산출물·요구사항 추적

### 입력과 검사 경계

초기 입력은 commit으로 고정한 UTF-8 JSON과 Markdown이다. 요구·추적의 정본은 JSON으로 두며 Markdown은 사람이 검토하는 산출물로 사용한다.
HWP/HWPX/PDF/Office·임의 YAML 처리·원문 OCR은 이후 입력 어댑터다. 미지원 파일이 필수 산출물이면 review_required이며 통과로 생략하지 않는다.
Markdown의 링크를 따라 네트워크를 조회하거나 HTML·스크립트를 실행하지 않는다.

새 문서 입력 계층은 전체 Git 파일 목록을 남기고 등록한 산출물의 바이트를 한 번 캡처한다. 검사와 digest 계산에 같은 바이트를 쓴다.
초기 상한은 기존 입력 상한에 맞춰 전체 100파일, 파일당 256,000바이트, 전체 2,000,000바이트다. 초과는 오류이며 조용히 일부만 검사하지 않는다.
정규화 JSON은 기존 1MiB 상한 안에 둔다. 요구 최대 1,000개, 추적 연결 최대 10,000개, 조건 깊이 최대 16을 추가 상한으로 제안한다. 바이트 상한이 먼저 걸리면 오류다.
더 큰 실제 사업 입력을 지원하려면 성능·자원 시험 뒤 상한 정책을 별도 개정한다.

### 세 검사의 의미

| 검사 | 자동 확인 | 자동으로 확정하지 않는 것 |
| --- | --- | --- |
| trace_integrity | 요구 ID 유일성, 존재하는 참조, 요구→설계→시험 계획·결과 연결, 허용 관계 | 설계·시험이 요구 의미를 충분히 다루는지 |
| artifact_structure | 필수 산출물 등록, 같은 commit의 내용 digest, 필요한 구조·항목 | 문서 내용 품질, 검수 수락 |
| result_binding | 시험 결과·검토 기록의 신뢰한 발행자, 대상 입력·도구·시점·서명 | JSON에 passed라고 적었다는 이유만으로 실제 시험 성공 |

출처를 검증할 시험 어댑터가 없으면 검토 필요로 남긴다. 초기 합성 시험 기록은 합성임을 명시하며 실제 업무 기능 시험으로 표현하지 않는다.
문서 품질·검수 수락이 필요한 요구는 자동 검사 성공 후에도 현재 산출물 digest에 묶인 독립 검토를 기다린다.

### 전체 실행

1. 합성 프로필 PROJECT-DELIVERY-REFERENCE에 산출물 추적 팩과 기존 로깅 연결 팩을 잠근다.
2. 요구 8개를 표시한다. 적용 확인 6개·승인 제외 1개·미확정 1개이며, 적용 6개 중 현재 단계 5개·후속 단계 1개다.
3. 현재 단계 5개를 검증 충족 2개·추적 누락 1개·검토 대기 1개·자료 미검증 1개로 표시한다. 단계 게이트는 열리지 않는다.
4. 작업 안내는 보완할 연결·산출물·확인할 사실·검토 담당자를 요구별로 제시한다.
5. 구조화 추적·산출물의 수정 초안을 검토하고 새 commit에 적용한다. 사실·시험 결과·검수 승인을 자동으로 만들어 내지 않는다.
6. 적용성의 미확정 1개는 사실 확인과 독립 검토 후 제외로 확정하는 합성 시나리오를 사용한다.
7. 새 commit에서 문서 검사와 필요한 기존 로깅 검사를 다시 실행하고, 자료와 서명 검토를 현재 입력에 결합한다.
8. 현재 단계 5개가 검증 충족되고 승인 제외 2개·후속 단계 1개가 남은 결과와 증적을 생성한다. 해당 단계만 통과하며 전체 프로젝트 완료로 표시하지 않는다.

### 수정 지원

초기 자동화는 누락된 항목·연결의 초안과 다음 작업을 생성한다. 새 파일·수정 범위를 먼저 보여 주고, 승인한 경로·기준 digest에만 새 작업 복사본으로 적용한다.
승인된 요구·팩·시험 결과·검토 기록을 자동 삭제·변경하지 않는다. 빈 양식을 채웠다는 이유로 pass를 만들지 않는다.
기존 Python 수정기의 제한을 문서에 맞춰 느슨하게 풀지 않는다. 문서 적용기는 별도이며 충돌·범위 초과·기준 변경 시 중단한다.
v0.10에는 모델 호출이 필수가 아니다. 계약 원문이나 산출물 본문을 외부 AI에 전송하는 기능은 포함하지 않는다.

## 6. 충족 현황과 단계 게이트

적용성과 수행 상태를 다른 축으로 저장한다. RequirementAssessment의 상태는 satisfied / unsatisfied / review_required / error / not_evaluated / stale / not_due로 제안한다.
satisfied는 적용 확인·기한 도래·모든 필수 검사·필요한 독립 검토·유효한 증적이 현재 입력에 일치할 때만 가능하다.
예외 승인은 충족으로 집계하지 않고 별도 표시한다. 법령상 의무를 면제하는 경로는 만들지 않는다.

전체 분모 T는 잠금본의 고유 요구 수다. T = 적용 확인 A + 승인 제외 E + 미확정 U다.
현재 단계 대상 D는 A의 부분집합이고 나머지는 후속 단계 F다. 화면 검색·팩별 필터가 T를 바꾸지 않는다.
같은 적용 요구의 검사가 여러 개여도 요구 수는 한 번만 집계한다. 하나라도 필수 검사가 미완료면 해당 요구는 satisfied가 아니다.
초기 화면은 비율보다 개수와 남은 작업을 우선한다. 단계 검증 비율을 추가한다면 satisfied / D를 명시하고 D=0은 ‘해당 단계 대상 없음’으로 표시한다.
미확정·미검증·후속 단계가 남아 있는데 전체 ‘100% 준수’로 표시하지 않는다. 적용 제외와 예외를 분자에 넣지 않는다.

기한 전 판정은 승인한 팩의 단계 조건과 프로필에만 근거한다. 문서의 임의 날짜·UI 숨김·작성자의 기한 변경으로 필수 검사를 미루지 않는다.
단계 게이트는 승인된 프로필·팩·잠금본, 미확정 적용성 U=0, 단계 필수 검사·검토·증적을 모두 확인한다. 초기 버전은 잠금본 안의 미확정 적용성이 남으면 보수적으로 검토 필요로 둔다.
예상 commit과 사용할 프로필·잠금본의 신뢰 기준은 검사 checkout 밖에서 제공한다. 서명된 것처럼 보이는 사용자 파일 자체를 신뢰 루트로 쓰지 않는다.
CLI 종료 코드는 0=해당 단계 통과, 2=확정 미충족, 3=미확정·검토·미검증·stale, 4=입력·서명·팩·검사 오류로 한다.
여러 사유가 있으면 error → review_required → deny → allow의 우선순위와 전체 사유 목록을 보존한다.
기존 코드 필수 검사와 새 단계 조건은 AND로 연결한다. 과거 archive 무결성 확인이나 일부 팩의 성공을 현재 게이트 성공으로 재사용하지 않는다.
새 증적은 project_evaluation 전용 포맷·검증기로 다룬다. 기존 archive 형식의 필드를 임의로 바꾸지 않는다. 역사적 무결성 확인에는 release_approval=false를 유지한다.

## 7. 무효화와 변경 영향

검토 대상 subject_digest는 프로필·잠금본·대상 commit·산출물 manifest·검사 도구를 결합하며 검토·서명 기록 자신을 포함하지 않는다.
ReviewDecision은 이 subject_digest에 결합한다. 최종 evaluation_digest는 subject_digest와 검증한 review_set_digest·평가 결과를 결합한다. 자기 서명이나 최종 승인 결과를 입력에 넣는 순환을 만들지 않는다.
기존 결과를 수정하지 않고 새 평가와 부모 참조를 만든다. 필요한 자료가 바뀌면 현재 평가·검토는 stale 또는 오류다.
초기 버전은 commit이 바뀌면 관련 게이트를 다시 검사하고 필요한 승인을 다시 받는 보수적 규칙을 사용한다.
선택적 영향 분석은 무엇을 다시 확인할지 안내하는 용도다. 관련 없는 변경이라고 추정해 이전 통과를 자동 재승인하지 않는다.

| 변경 | 처리 |
| --- | --- |
| 프로필 사실·단계·범위 | 적용성·잠금본·평가·승인 재확인 |
| 규정 원문·팩 버전·필수 작업 | 새 팩과 독립 승인·새 잠금본. 이전 근거 보존 |
| 산출물·추적·시험 결과 | 새 commit·새 검사·대상에 묶인 검토 |
| 검사 도구·스키마 | 도구 digest 변경·새 평가. 구형 계약의 조용한 수용 금지 |
| 키·정책·승인 철회 | 현재 사용 거부. 역사적 기록과 현재 사용 가능 여부 분리 |

## 8. 제안 파일·명령 경계

R7-A~D와 project validate-profile·profile-demo·validate-pack·pack-demo·assess-applicability는 구현했다. 나머지 파일과 명령은 구현 예정 인터페이스다. [실행 안내](PROJECT_PROFILE_RUNBOOK.md)를 따른다.

| 단위 | 제안 파일 | 집중 검증 |
| --- | --- | --- |
| R7-A | govcode_harness/contracts/project-profile.schema.json, rule-pack.schema.json, project-evaluation.schema.json, project-common.schema.json; tests/fixtures/project-compliance/ | 형태·참조·enum·중복·범위·잘못된 입력 |
| R7-B | govcode_harness/project_profile.py; tests/test_project_profile.py | 개정·승인·미확정·자기 승인·다른 프로젝트 |
| R7-C | govcode_harness/rule_pack.py; rule_packs/delivery-trace/; rule_packs/privacy-logging/; tests/test_rule_pack.py | 발행·서명·의존성·충돌·철회·만료·역행 |
| R7-D | govcode_harness/applicability.py; tests/test_applicability.py | 참·거짓·미확정, 제외 승인, unknown의 not·all·any |
| R7-E | govcode_harness/artifact_snapshot.py, delivery_trace.py; tests/test_delivery_trace.py | 같은 바이트·경로·구조·추적·신뢰한 결과 결합 |
| R7-F | govcode_harness/project_assessment.py, work_items.py, document_proposal.py; tests/test_project_assessment.py | 분모·상태·미검증·기한·승인·수정 범위·무효화 |
| R7-G | govcode_harness/project_cli.py, project_gate.py; control_plane.py·ui의 제한 확장 | CLI·역할·화면·AND 게이트·구형 호환 |
| R7-H | govcode_harness/project_evidence.py; tests/test_project_evidence.py | 새 기록 투영·같은 바이트·부모·서명·권한·보관·복구 |
| R7-I | govcode_harness/project_reference.py; tests/test_project_reference.py; docs/PROJECT_REFERENCE_RUNBOOK.md | 두 분야의 전후 실행·보관·검증·회귀·독립 검토 |

CLI는 project validate-profile / pack validate / project plan / project assess / project gate / project-demo로 제안한다.
plan은 다음 작업만 생성하고 원문을 변경하지 않는다. assess는 새 평가를 만들며, gate는 신뢰한 예상 commit과 subject_digest·최종 evaluation_digest를 다시 확인한다. 같은 대상의 plan 반복은 요구·행동·subject_digest로 작업을 식별해 중복 생성하지 않는다.
기존 scan·verify·gate·demo의 기본 계약은 유지한다. 새 명령과 API 요청의 누락·오류가 기존 모드로 암묵 전환되지 않아야 한다.
API는 /v1/projects 하위의 profiles·pack-locks·work-items·evaluations를 자원별로 분리한다. 기존 실행 ID만으로 새 객체 접근 권한을 얻을 수 없다.
증적에는 ID·상대 참조·digest·판정·검토 근거 참조만 담는다. 계약·요구 원문·내부 문서·토큰은 원문 없는 일반 증적과 분리한다. 경로·제목에 민감 정보가 있으면 외부 요약에는 불투명 별칭을 쓰고 원문 매핑은 기관 내부에 보호한다.

## 9. 인수 시험 목록

| ID | 시나리오 | 통과 조건 |
| --- | --- | --- |
| A01 | 유효·미완성 프로필 | 미확정 사실이 false·제외·자동 승인으로 바뀌지 않음 |
| A02 | 프로필 개정·승인 | 독립 승인과 버전 고정, 과거 프로필과 다른 기관 재사용 거부 |
| A03 | 팩 서명·출처·범위 | 미검증 출처를 법령상 확정 의무로 활성화하지 않음 |
| A04 | 잠금본과 팩 의존성 | 누락·충돌·순환·만료·철회·역행 거부 |
| A05 | 조건 언어 | 3값 논리·형식 오류·깊이 제한, 임의 코드 실행 없음 |
| A06 | 문서 경로와 자원 | symlink·경로 탈출·중복 JSON 키·용량 초과·필수 미지원 파일 거부 |
| A07 | 요구와 추적 | 중복 ID·없는 설계/시험 ID·다른 프로젝트 참조·잘못된 관계 검출 |
| A08 | 허위 충족 자료 | 파일 존재·필수 제목·passed 문자열만으로 충족 처리하지 않음 |
| A09 | 담당자 검토 | 자기 승인·과거 내용 승인·임의 문서 승인 문구·철회된 서명 거부 |
| A10 | 분모와 화면 상태 | T=A+E+U, 현재·후속 단계 분리, 제외·예외가 충족으로 집계되지 않음 |
| A11 | 작업 안내와 수정 | 요구별 보완 항목·담당자 표시, 승인 범위만 새 commit에 적용, 원본·시험·팩 불변 |
| A12 | 재검사와 stale | 프로필·팩·commit·산출물·도구·검토 변경 후 과거 통과 재사용 거부 |
| A13 | 두 분야 연결 | 새 산출물 검사가 기존 로깅 오류·미분석·필수 검사를 면제하지 않음 |
| A14 | 권한과 입력 주입 | 다른 기관/프로젝트의 읽기·변경 거부, Markdown/팩 지시·HTML·외부 URL 실행 없음 |
| A15 | 전체 참조 실행 | 요구 8개의 전후 상태·현재 단계 통과·후속 단계 1개·증적을 일관되게 생성 |
| A16 | 증적과 복구 | 같은 캡처 바이트 결합, 변조·부모 누락 거부, 서명 보관·복구 후 이력 확인 |
| A17 | 구형 계약과 회귀 | 기존 320개를 건너뜀·실패 없이 재실행, 기존 명령의 종료 코드·입력 모드 유지 |
| A18 | 새 독립 표본과 검토 | 개발 표본과 분리한 추적 결함 표본 공개 평가, 위험 통과 0건, 미지원 별도 보고, 독립 지적 해소 |

합성 표본은 우선 개발 24건·독립 인수 24건으로 설계한다. 각 세트에 정상 8·차단 결함 8·미확정/미지원 8을 사전 분류한다.
차단 결함이 allow가 되면 1건이라도 중단한다. 정상·차단·미지원의 분모와 판정을 따로 보고한다.
독립 인수 표본을 구현 보정에 사용했다면 진단 표본으로 전환하고 새로운 독립 표본으로 다시 확인한다.
표본과 시험은 구현 때 작성한다. 이 문서를 작성했다고 위 시험을 수행한 것으로 표시하지 않는다.

## 10. 공식 자료의 후속 입력 후보

다음 링크는 2026-10-29에 게시 페이지 또는 표제를 확인한 **자료 수집 후보**다. 기관 적용 조문과 원문 전체를 확정한 목록이 아니다.

| 자료 | 확인한 범위 | 팩에 넣기 전 할 일 |
| --- | --- | --- |
| [행정기관 및 공공기관 정보시스템 구축·운영 지침](https://www.law.go.kr/LSW/admRulLsInfoP.do?admRulSeq=2100000252582) | 조회된 페이지의 2025-1호·2025-01-02 표제. 2026-10-29 현행 적용본이라고 확정하지 않음 | 기준일 적용본·조문·부칙·기관/사업 조건을 확인하고 자료 digest와 검토자 기록 |
| [NIA SW사업자를 위한 정보시스템 감리준비 및 대응 가이드](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=25210&cbIdx=99860) | 2023-02-06 게시 페이지와 PDF 첨부명 | 원문·개정본·사업 계약과의 관계를 확인. 안내 자료를 법령상 의무로 승격하지 않음 |
| [NIA 2022년 감리 발주관리·수행 가이드 개정 공지](https://www.nia.or.kr/site/nia_kor/ex/bbs/View.do?bcIdx=24365&cbIdx=99860) | 2022-04-11 게시 페이지와 첨부 목록 | 원문과 후속 개정·적용 조건 확인, 선택한 요구와 검토 책임 명시 |
| 기관 제공 제안요청서·계약·산출물 목록 | 제공되지 않음 | 사용 권한·문서 버전·필수/권고 구분·검토 승인 후 입력 |

첨부 한국어 PDF는 열람하지 않았다. 후속 수집 시 렌더링·OCR와 원문 대조를 사용한다.
첫 실행 팩은 합성 예시 요구만 포함하며, 기존 REG-LOG-008 등의 미확정 적용성을 이번 계획으로 해소한 것으로 취급하지 않는다.

## 설계 문서 작성 정책 연결

문서 작성·수정 제안은 [공통 작성 정책](../govcode_harness/document_assets/DOCUMENT_WRITING_POLICY.md)을 적용한다.
현재 `project document-kit`은 공통 형식의 초안과 별도 검토 메모를 생성한다. [실행 안내](DOCUMENT_GENERATION.md)를 따른다.
R7-F의 문서 제안은 같은 정책과 원문 대조 절차를 사용해야 한다. 구조 검사 누락·미지원·수동 검토를 통과로 바꾸지 않는다.
작성 정책은 법적 의무나 충족 평가를 대신하지 않으며, 생성 결과를 기존 평가·승인 증적으로 자동 등록하지 않는다.
