# 현재 단계 게이트와 증적 보관 안내

## 현재 단계 판정

project gate는 원본 평가 입력을 다시 검증한다. 기존 root gate 명령의 코드 검사 의미는 바꾸지 않는다.
--expected-commit·--expected-subject-digest·--expected-evaluation-digest는 신뢰한 호출자가 checkout 밖에서 제공한다.
이 명령은 project assess와 같은 원본 인수에 --code-evidence·--code-context·--evidence-store·--evidence-id를 연결한다.

승인된 프로필의 code_checks_required가 미확정이면 검토 필요다. false여도 코드 파일이 있으면 조용히 건너뛰지 않는다.
true면 기존 코드 게이트를 현재 commit·기관·프로젝트·서명 정책 묶음으로 실제 검증한다.
코드 정책 문맥은 bundle·양의 min_sequence와 선택 revocations·exceptions·with_iron_laws를 갖는 보호된 JSON이다.
코드·문서가 준비돼도 실제 저장 증적이 없으면 통과하지 않는다. 저장 증적은 현재 후보·평가·subject·commit·단계에 정확히 일치해야 한다.
기존 코드 검사와 새 단계 조건은 AND다. 오류→검토 필요→미충족→통과 순서와 모든 사유를 보존한다.
현재 단계 대상이 0개면 자동 전체 준수나 단계 통과로 표시하지 않는다.

## 증적 보관

project evidence-create는 --root·--trust·--tenant-id·--project-id·--private-key·--key-id로 새 비공개 보관기를 만든다.
보관기 설정 파일은 root와 선택 checkpoint만 갖는다. 설정·신뢰 목록·checkpoint는 검사 대상 밖에서 보호한다.
project evidence-put은 원본 평가 인수와 --store·--signer-key·--signer-id·--expected-commit·--retain-until을 받는다.
선택 --legal-hold·--parent-id·--code-evidence·--code-context로 보존 잠금·이전 기록·코드 검사를 연결한다.
보관기는 원본에서 현재 후보를 다시 계산한다. unsigned 보고서나 verified=true만 받아 봉인하지 않는다.

표 1. 역할별 보관 작업

| 명령 | 필요한 별도 서명 권한 | 추가 인수 |
| --- | --- | --- |
| evidence-read | auditor | evidence-id |
| evidence-hold | operator | evidence-id·enabled=true/false |
| evidence-delete | operator | evidence-id |
| evidence-backup | operator | 새 output |
| evidence-restore | operator | backup·새 output·기준 head digest·최소 sequence |

읽기·hold·삭제·백업에는 store·trust·authorization과 보관 journal의 signer-key·signer-id를 제공한다.
서명 권한은 project evidence-authorize로 만들 수 있다. action·대상·기관·프로젝트·store_id·시각·nonce와 매개변수 digest를 결합한다.
read의 권한은 auditor이며 나머지 작업은 operator다. set_hold는 enabled 값, backup·restore는 실제 새 목적지에 결합한다.
다른 대상·범위·역할·만료한 요청·재사용한 nonce·바뀐 enabled/목적지는 거부한다.
새 권한의 출력 파일과 개발 키는 비공개로 보관한다. 프로그램은 CLI 응답에 키나 토큰을 출력하지 않는다.

## 보존·백업·복구

retain_until은 운영자가 선택한 보관 정책이며 법정 접속기록 기간이 아니다.
hold가 있거나 기한 전이면 삭제하지 않는다. 활성 자식이 참조하는 부모도 삭제하지 않는다.
백업은 검증한 같은 캡처 바이트로 만든다. 새 경로만 사용하며 원래 보관기나 백업 내부로 복구하지 않는다.
restore에는 --expected-head-digest와 --minimum-sequence를 외부 보호 기록에서 제공한다. 백업 자신에게서 값을 읽어 신뢰했다고 해석하지 않는다.
복구한 보관기는 기존 store_id와 서명 이력을 보존하고 새 복구 이벤트를 추가한다.
원래 보관기가 없어도 복구를 실제 시험하되, 이 참조 보관기가 WORM 저장소나 운영 키 관리까지 제공한다고 주장하지 않는다.

## 역사적 확인과 현재 통과의 구분

과거 읽기는 signature·digest 무결성 확인이며 release_approval=false다.
현재 통과에는 원래 프로필·팩·철회·commit·검사·검토를 다시 검증하고 실제 현재 저장 객체도 대조해야 한다.
전체 로컬 파일을 과거 상태로 되돌린 경우 외부 보호 checkpoint가 없으면 탐지를 보장하지 않는다.
전체 합성 실행과 실제 화면은 [참조 실행 안내](PROJECT_REFERENCE_RUNBOOK.md)를 따른다.
