# R7-F~I 랄프 루프 순차 구현 계획

## 승인 범위와 완료 기준

사용자는 로드맵의 작업을 랄프 루프로 순차 진행하도록 요청했다. 현재 구조 정리·R7-E와 553개 시험을 기준선으로 보존한다.
이번 범위는 남은 R7-F~I의 로컬 합성 참조 구현과 검증이다. 기관 운영 승인·실데이터·원격 CI 활성화·새 릴리스는 포함하지 않는다.
분야는 기존에 선택한 사업 산출물·요구사항 추적과 첫 개인정보 로깅 사례로 유지한다. 새 법령 의무를 추정하지 않는다.

## 반복 방식

원래 Ralph Loop의 setup-ralph-loop.sh와 stop-hook.sh를 .runtime/ralph-r7에서 실제 호출한다.
Codex의 자동 종료 훅이 설치됐다고 표현하지 않는다. 체크포인트 어댑터가 같은 프롬프트와 상태를 보존하며 각 반복의 결과·실패·수정·검증을 기록한다.
종료 문구는 GOVCODE_R7_LOCAL_REFERENCE_COMPLETE다. 60회 상한에 도달해도 완료 조건이 충족되지 않으면 미완료로 남긴다.

표 1. 순차 단계와 종료 조건

| 단계 | 구현 | 다음 단계로 진행할 조건 |
| --- | --- | --- |
| R7-F | 현재 입력의 충족 평가·독립 산출물 검토·작업 안내·승인된 문서/추적 초안 적용 | 분모·미확정·후속 단계·자기 승인·stale·수정 범위 음성 시험 통과 |
| R7-G | 프로젝트 CLI·현재 단계 게이트·쉬운 현황 화면·서버 권한 | 원본 재검증·기존 코드 게이트 AND·다른 범위/역할·결과 주입 거부 |
| R7-H | 원문 없는 새 평가 증적·서명·보관·권한·hold·백업·복구 | 변조·부모 누락·롤백·기한/hold·현재 통과 재사용 거부 |
| R7-I | 요구 8개·두 분야·수정/재검사/검토·화면·증적의 전체 합성 인수 | 기존 553개 유지·독립 표본·실제 실행·설치 패키지·최종 독립 검토 |

각 단계에서 테스트 우선 구현→집중 검사→독립 검토→지적 수정→체크포인트를 반복한다. 다음 단계는 선행 계약과 시험이 안정된 뒤 착수한다.
최종 종료에는 전체 회귀에서 실패·오류·건너뜀 0개, 실제 통합 실행, 코드·시험 digest 동결과 최종 APPROVED가 필요하다.

## 고정할 공통 계약

평가는 repo·전체 commit·index_path와 원래 서명 profile/lock/feed·외부 보호 digest·최소 순번·신뢰 목록·검사 도구를 입력받는다.
호출자가 만든 unsigned 검사 보고서나 verified=true를 권한으로 신뢰하지 않는다. 적용성과 산출물을 현재 원본으로 다시 검증한다.
검토 subject는 schema/context/scope·commit·profile·lock·artifact manifest·tool digest를 결합하며 승인 자신을 포함하지 않는다.
전체 분모는 잠금본의 고유 요구다. 적용·승인 제외·미확정을 모두 보존하고 현재 단계·후속 단계를 구분한다.
미확정은 false나 제외로 바꾸지 않는다. 독립 검토는 현재 subject·요구·관련 산출물 digest와 유효 구간에 결합한다.
기한은 승인된 프로필·팩 단계에서만 도출한다. 변경하면 새 프로필·잠금·검사·승인이 필요하다.

화면은 개수·다음 행동·검토 이유를 먼저 보여 준다. 코드 검사와 문서 검사 성공을 전체 준수 인증으로 표시하지 않는다.
문서 초안은 공통 작성 정책을 적용하고 검토 메모와 분리한다. 적용은 서명 author 제안·독립 approver 승인·현재 기준 digest·허용 경로를 요구한다.
기존 저장소를 덮어쓰지 않고 고정 commit에서 새 작업 복사본과 새 commit을 만든다. 규정 팩·시험 결과·검토·실행 도구·CI·시험 삭제는 수정 대상으로 허용하지 않는다.

새 증적은 기존 archive 형식과 구분한다. 원문·계약·문서 본문·키·토큰 없이 ID·digest·상태·서명 검토 근거를 보관한다.
보관·복구의 무결성 확인은 역사적 확인이며 현재 gate allow를 만들지 않는다. 외부 보호 checkpoint 없는 전체 로컬 롤백 탐지는 보장하지 않는다.

## 단계 간 실행 계약

R7-F의 assessment.assess는 원래 입력을 다시 검증하고 project_assessment_report를 만든다.
subject_digest는 현재 입력, evaluation_digest는 상태·실행 증명·독립 검토 집합을 결합한다. ready_for_stage는 게이트 통과가 아니다.
모든 현재 범위 author 행위자는 다른 키로도 산출물 검토를 승인하지 못한다. 서명 팩·프로필 작성자도 승인에서 분리한다.

R7-G의 stage_gate.prepare(request, expected_commit, code_evidence=None, code_context=None, expected_subject_digest=None, expected_evaluation_digest=None)는 원본 재평가와 현재 HEAD를 확인한다.
code_checks_required 사실은 승인된 프로필에서만 읽는다. 미확정은 검토 필요다. false여도 코드 파일이 있으면 검토 필요다.
필요한 코드 검사는 기존 gate.evaluate를 실제 현재 commit·범위·서명 정책 묶음으로 호출한다. 요청 본문의 code_passed 같은 값은 사용하지 않는다.
후보는 assessment, code_required, code_receipt_digest, candidate_digest, outcome(ready_for_evidence/deny/review_required/error), reason_codes를 담는다.
코드 결합 digest는 현재 증적 manifest·신뢰한 코드 정책 문맥·판정·검사 프로필을 결합한다. 검증 때마다 바뀌는 시계 표시만으로 digest가 달라지지 않아야 한다.
최종 stage_gate.evaluate는 현재 후보를 다시 만들고 R7-H 보관기의 실제 저장 서명 증적과 일치할 때만 allow를 반환한다. 미구현·누락 보관 증적은 통과시키지 않는다.
현재 단계 대상이 0개면 자동 전체 준수나 단계 통과로 표시하지 않는다.

R7-G 화면/API는 기존 loopback 서버·토큰 인증·기관/프로젝트/역할 분리를 유지한다.
프로젝트 문맥과 파일 경로는 관리자 설정에서만 읽고 요청 본문으로 덮어쓰지 않는다. 조회는 원문 없는 현황·작업을 제공한다.
독립 검토 API는 authenticated approver가 현재 subject와 요구·산출물 digest를 확인한 후 서버가 자기 actor로 서명한다. actor·키·경로를 본문으로 지정할 수 없다.

R7-H의 ProjectEvidenceStore.put은 원본 request와 expected_commit에서 stage_gate.prepare를 다시 실행해 저장한다. 사용자가 제공한 unsigned 보고서만 봉인하지 않는다.
저장 객체는 새 형식의 원문 없는 projection과 서명 metadata다. metadata는 store_id/object_id·subject/evaluation/candidate/code 결합 digest·보존 기한·hold·부모를 포함한다.
ProjectEvidenceStore.verify_receipt는 실제 현재 저장 객체·서명·투영·부모 사슬과 요청한 후보의 정확한 digest를 대조한다.
보관기는 auditor의 읽기와 operator의 hold·삭제·백업·복구를 서명 권한·범위·nonce로 검증하고 서명 journal에 남긴다.
백업과 복구는 검증한 같은 캡처 바이트를 사용한다. 외부 보호 head/최소 순번을 요구하며 새 경로에만 복구한다.
역사적 읽기는 release_approval=false다. 기존 archive 형식과 검증기를 몰래 확장하지 않는다.

## 실행 결과

F→G→H→I를 순차 구현했고 각 단계 검토 지적을 재현·수정했다. 실제 저장 증적을 연결한 뒤 G/H의 최종 통과도 확인했다.
전체739개·별도 계약 인수24개·실제 브라우저·프로젝트 밖 설치 실행을 통과했다. [완료 보고](../R7_COMPLETION_REPORT.md)와 [검증 기록](../VALIDATION.md)을 따른다.
현재 로컬 미릴리스이며 실제 기관 운영과 구분한다.

## 이후 배포

이 문서의 미릴리스 표시는 구현 당시의 상태다. 사용자 배포 요청에 따라 이 변경을 v0.11.0 사전 릴리스에 포함한다. [릴리스 범위](../releases/v0.11.0.md)를 따른다.
