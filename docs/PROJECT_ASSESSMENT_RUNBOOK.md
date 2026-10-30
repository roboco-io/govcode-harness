# 작업 안내·충족 평가·문서 수정 실행 안내

## 목적과 현재 경계

R7-F는 현재 승인한 프로필·규정 팩·commit의 산출물과 실행 증명·독립 검토를 다시 확인하고 요구별 상태와 다음 작업을 만든다.
파일 생성이나 검사 통과만으로 요구가 충족됐다고 표시하지 않는다. 전체 요구 분모와 미확정·제외·후속 단계는 계속 표시한다.
이 기능은 로컬 합성 참조이며 실제 기관 승인·검수·법적 준수 인증이 아니다.

## 평가와 다음 작업

`project assess`는 원래 서명 자료를 다시 검증한다. `project plan`은 같은 검증에서 결정적 작업 목록을 만든다.
두 명령에는 --repo, --commit, --index, --tenant-id, --project-id, --profile-registry, --lock, --trust,
--revocations, --expected-revocation-digest가 필요하다. 경로·신뢰 목록·최소 순번은 검사 checkout 밖에서 관리한다.
--result-tools와 반복 --result-receipt는 시험 실행 증명, --applicability-review는 적용성 검토, --artifact-review는 독립 산출물 검토를 연결한다.
프로필 보호 기준점은 --profile-checkpoint, 최소 버전은 --min-sequence·--min-revocation-epoch·--min-profile-revision으로 제공한다.
입력 형태와 실제 원본 검증은 [산출물 실행 안내](ARTIFACT_TRACE_RUNBOOK.md)를 따른다. unsigned 보고서를 입력해 재승인하는 모드는 없다.

표 1. 요구 상태와 의미

| 상태 | 의미 |
| --- | --- |
| satisfied | 현재 단계의 적용 요구에서 필수 검사와 필요한 독립 산출물 검토가 현재 입력에 일치한다. |
| unsatisfied | 확정한 구조·추적·시험 실패 또는 검토 거절이 있다. |
| review_required | 적용 조건·지원 범위·검토가 미확정이다. |
| not_evaluated | 필수 시험 실행 증명 등이 아직 없다. |
| error | 원본·범위·서명·구조 검증 오류가 있다. |
| not_due | 승인된 프로필·팩에 따른 후속 단계 요구다. |
| not_applicable | 근거와 독립 적용성 검토로 제외를 승인했다. |
| stale | 현재 입력과 맞지 않아 다시 검사·검토해야 한다. |

분모 T는 고정 잠금본의 고유 요구 수이며 T=적용+승인 제외+미확정이다. 적용 요구는 현재 단계와 후속 단계로 나눈다.
제외·예외·후속 단계를 충족 수에 넣지 않는다. 오류나 미확정을 숨겨 전체 100% 준수로 표시하지 않는다.
ready_for_stage는 다음 단계 검토가 가능하다는 평가 결과이며 gate allow가 아니다.
작업 ID는 요구·행동·현재 subject로 정한다. 같은 입력의 반복 계획이 같은 작업을 새로 중복 생성하지 않는다.

## 독립 산출물 검토

검토는 project_artifact_review의 실제 approver 서명을 사용한다. 현재 subject·요구 참조·관련 산출물 digest 전체와 유효 구간에 결합한다.
검토 대상 subject에는 commit·프로필·잠금본·산출물 manifest·도구 digest를 넣고 승인 자신은 넣지 않는다.
같은 기관·프로젝트에서 author 역할이 있는 행위자와 원래 프로필·팩 작성자는 다른 키로도 산출물을 승인할 수 없다.
문서 안의 ‘승인’ 문구와 예전 subject의 서명을 승인으로 인정하지 않는다. 거절과 검토 필요도 별도 상태로 유지한다.

## 문서 제안·승인·새 복사본 적용

다음 명령은 인수를 생략하면 안전하게 오류를 반환한다. 실제 경로와 서명 키는 승인된 로컬 환경에서 제공한다.

- project propose-documents는 --repo·--commit·--index·--changes·--trust·--tenant-id·--project-id·--private-key·--key-id·--expires-at·--output을 받는다.
- project approve-documents는 --proposal·--trust·--private-key·--key-id·--expires-at·--output과 선택 --decision을 받는다.
- project apply-documents는 --repo·--proposal·--approval·--trust·--output을 받는다.

changes는 경로에서 새 UTF-8 텍스트로 연결하는 비공개 JSON이다. 제안과 승인 파일도 비공개로 보관한다. 제안에는 검토할 새 문서 본문이 포함된다.
CLI의 공개 응답은 digest와 처리 상태만 출력한다. 제안 서명을 산출물 검토나 요구 충족 승인으로 재사용하지 않는다.
등록된 설계 Markdown과 추적 인덱스의 제한된 보완만 지원한다. 요구·정책·시험 계획/결과·검토 기록·실행 코드·시험·CI·도구 지침 파일은 수정하지 않는다.
설계 문서라고 등록해도 AGENTS.md·CLAUDE.md·정책 파일과 도구 설정 경로는 허용하지 않는다.
추적은 기존 연결을 삭제하거나 다른 대상으로 돌리지 않는다. 누락 연결 추가와 승인한 설계 변경의 참조 digest 갱신만 허용한다.

적용은 원본을 수정하지 않고 새 비공개 작업 복사본과 commit을 만든다. 새 commit의 실제 부모는 원본 commit이다.
원격 저장소·필터·훅·전체 이력은 실행하거나 가져오지 않는다. 원본이 바뀌거나 안전하지 않은 Git 설정·경로가 있으면 중단한다.
출력은 실제 원본 작업 루트나 Git 메타데이터 내부일 수 없다. 하위 폴더·경로 별칭을 사용해 이 경계를 우회할 수 없다.
문서에는 [공통 작성 정책](../govcode_harness/document_assets/DOCUMENT_WRITING_POLICY.md)을 적용한다. 구조 검사의 의미와 수동 사실 대조를 구분한다.
적용 후에는 새 commit에서 필요한 코드·문서 검사와 독립 산출물 검토를 다시 수행해야 한다.
