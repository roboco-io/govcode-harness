# 폴더 구조 정리와 R7-E 산출물·추적 검사 구현 계획

## 목적과 기준

사용자는 현재 폴더 구조를 먼저 리뷰·리팩토링하고 다음 단계인 R7-E를 진행하도록 요청했다.
기준은 v0.10.0과 기존 회귀 시험 439개다. 기존 명령·데이터·서명 의미와 작성 정책을 유지한다.
R7-F~I 전체 구현이나 원격 게시·새 릴리스는 이번 범위가 아니다.

## 구조 리뷰와 결정

현재 실행 코드는 govcode_harness에 있고 apps와 packages는 설계 경계와 계약 자료를 담는다.
실행 코드가 없는 디렉터리를 실행 패키지로 오해하지 않도록 구조 안내를 추가한다.
프로젝트 프로필·규정 팩·적용성·문서 기능은 govcode_harness/project에 모은다.
기존 루트 모듈은 같은 모듈 객체를 제공하는 호환 진입점으로 남긴다. 스키마·UI·작성 정책의 자료 경로와 서명 형식은 바꾸지 않는다.
검사 도구 digest는 하위 실행 코드·계약·자료 변경도 반영한다. 이동 전의 도구 결과를 새 도구의 결과로 재사용하지 않는다.
기존 코드 검사·보관·모델 기능의 대규모 이동과 tests의 일괄 재배치는 이번에 하지 않는다.

## 실행 순서와 소유 경계

표 1. 구현과 검증 순서

| 단위 | 변경 | 검증 기준 |
| --- | --- | --- |
| T1 구조 정리 | project 하위 패키지·호환 진입점·도구 digest | import 동일성·자료 접근·이전 CLI·439개 전체 회귀 |
| T2 문서 스냅샷 | project/artifact_snapshot.py | commit의 같은 바이트·전체 목록·경로·형식·용량·문서 전용 입력 |
| T3 산출물 추적 | project/delivery_trace.py | 요구·설계·시험·검토 참조·구조·신뢰한 시험 결과 결합 |
| T4 실행 통합 | project CLI·합성 예시·실행 안내 | 누락 발견→새 commit 수정→재검사, 미검증 자료는 검토 필요 |
| T5 검증 | 집중·전체 회귀·패키지 설치·독립 리뷰 | 기존 439개 유지·새 음성 표본·검토 지적 해소 |

T1의 전체 회귀를 확인한 뒤 T2와 T3를 구현한다. 입력과 검사 코드는 분리하고 통합에서 실제 경계를 검증한다.
기존 작업 폴더의 승인된 자료·검증 환경을 사용한다. 외부 저장소와 가이드 저장소는 수정하지 않는다.

## R7-E 입력과 출력 계약

입력은 명시한 전체 commit SHA, 기관·프로젝트 범위, commit 안의 JSON 산출물 인덱스다.
인덱스는 kind=project_artifact_index, schema_version=1, context=synthetic_reference, operational_approval=false,
tenant_id, project_id, artifacts, requirements, traces를 갖는다. artifacts와 traces는 기존 artifact_ref·trace_link 계약을 사용한다.
requirements는 기존 requirement_spec의 구조화 사본이다. 단독 인덱스 검사는 규정 팩·프로필·적용성의 검증을 대체하지 않는다.
검사 함수는 R7-D와 통합할 때 현재 검증한 요구 집합과 인덱스 집합을 정확하게 대조해야 한다.

전체 Git 파일 목록과 등록 산출물의 캡처 바이트를 분리한다. 내용 digest와 검사는 같은 캡처 바이트를 사용한다.
초기 상한은 전체 100파일·파일당 256,000바이트·총 2,000,000바이트다. 요구 1,000개·추적 10,000개 상한과 기존 JSON 1MiB 상한도 유지한다.
등록한 Markdown·JSON만 내용 검사한다. 필수 미지원 형식은 검토 필요로 남긴다. 링크·HTML·문서 지시를 실행하지 않는다.
코드 검사에서 Python 파일이 없을 때의 기존 오류는 유지한다. 문서 전용 입력의 검사를 코드 통과로 바꾸지 않는다.

trace_integrity는 ID 유일성·실재하는 참조·관계 방향과 요구→설계→시험 계획→결과→검토 연결을 확인한다.
artifact_structure는 필수 산출물·내용 digest·Markdown 제목 구조·JSON 형태를 확인한다.
result_binding은 신뢰한 발행자의 서명과 대상 commit·요구·산출물·도구·유효 구간을 검증한다.
서명 없는 passed 값과 문서 안의 승인 문구는 검증 성공으로 처리하지 않는다.

보고서는 error·review_required·defects_found·checks_passed를 구분하고 requirements_evaluated=false와 operational_approval=false를 유지한다.
검사 성공은 내용의 적절성·요구 충족·단계 통과·기관 승인이 아니다. 원문 대신 ID·digest·사유·다음 검토만 출력한다.
독립 검토·전체 충족 집계·단계 게이트·새 증적 보관은 R7-F~I에 남긴다.

## 인수와 검토

정상 추적, 끊긴 추적, 중복 ID, 다른 범위, digest 변조, symlink·gitlink·경로 탈출, 중복 JSON 키,
미지원 파일, 비 UTF-8, 과거·변조·범위 불일치 시험 결과, 입력 주입, dirty 작업 파일과 지정 commit의 분리를 검증한다.
기존 코드 게이트가 새 문서 검사로 면제되지 않는지 확인한다. 문서 초안은 공통 작성 정책을 적용하고 검토 메모와 구분한다.

## 구현 인터페이스 고정

T2의 collect(repo, commit, index_path, tenant_id=, project_id=, git=None, max_files=100, max_blob=256000, max_total=2000000)는 manifest·index·contents를 반환한다.
manifest는 format=govcode-project-artifact-snapshot-v1, tenant_id, project_id, commit_sha, index_path, index_digest, index_canonical_digest, inventory, artifacts, total_bytes, worktree_checked=false와 operational_approval=false를 담는다.
inventory는 전체 Git 파일의 path·sha256·size_bytes다. artifacts는 artifact_ref와 format(markdown/json/unsupported), status(captured/unsupported/encoding_error), reason_codes를 담는다.
contents는 산출물 ID에서 캡처한 bytes로 연결하는 비공개 자료이며 보고서에 복사하지 않는다. index 파일은 산출물 자신으로 등록할 수 없다.
manifest_digest는 manifest 전체의 canonical digest다. 인덱스와 산출물의 파싱에는 중복 JSON 속성·비표준 숫자·용량을 거부하는 같은 바이트 파서를 사용한다.
기존 snapshot.py에는 공통 capture가 전체 파일의 bytes·digest를 한 번 읽도록 추가하며 기존 collect의 코드 분류 결과는 유지한다.

T3의 inspect(collected, now=, expected_requirements=None, result_receipts=(), trust=None, allowed_result_tools=None)는 원문 없는 검사 보고서를 반환한다.
expected_requirements는 호출자가 현재 서명 팩에서 검증한 요구 집합이다. 없으면 구조 검사만 수행하며 requirement_authority=not_checked와 검토 필요를 유지한다.
모든 참조의 kind·ID·version·digest와 기관·프로젝트를 확인한다. 관계 방향은 requirement→design(implements), design→test_plan(verifies), test_plan→test_result(reports), test_result→review_record(reviews)다.
각 요구는 이어진 한 경로를 가져야 한다. required_artifacts의 ID도 모두 존재하고 해당 요구에서 도달하며 검토 기록까지 이어지는 경로 위에 있어야 한다. depends_on은 같은 종류끼리만 허용하고 순환을 거부한다.
Markdown은 첫 제목과 순서 있는 제목 단계 등 구조만 확인한다. 서술·사실·그림·병합의 의미 적절성은 수동 검토다. HTML 실행이나 링크 조회를 하지 않는다.

시험 실행 증명은 commit 밖에서 서명한 artifact_test_attestation으로 받는다. 결과 파일 안에 현재 commit을 포함시켜 순환 참조를 만들지 않는다.
서명 payload는 schema_version·context·tenant_id·project_id·operational_approval=false·actor_id·event_id·created_at·not_before·expires_at·commit_sha·artifact_manifest_digest·requirement_ref·result_artifact_ref·check_id·adapter_id·tool_digest·result(pass/fail)를 갖고 다른 필드는 거부한다.
신뢰 목록의 operator 역할을 검증한다. allowed_result_tools는 check_id별 adapter_id·tool_digest의 신뢰한 외부 설정이며 인덱스에서 가져오지 않는다.
필수 check_refs 전부를 요구별로 확인하고 중복·오래된 대상·서명 오류·다른 도구·만료를 오류로 처리한다. 증명이 없으면 검토 필요, 서명한 fail은 결함으로 남긴다.
검토 산출물의 승인 문구는 승인으로 인정하지 않으며 최종 요구 충족 판정은 R7-F에 남긴다.

index_canonical_digest는 파싱한 인덱스의 canonical digest다. 원본 바이트 digest와 함께 저장하여 캡처 이후의 파싱 객체 변경을 검출한다. 자체 digest만으로 외부 신뢰 권한을 부여하지 않는다.

서명 팩 연결 모드에서는 외부 도구 설정의 adapter_id를 검증한 팩의 check_specs와 대조한다. 같은 check_id에 서로 다른 어댑터가 선언되면 임의 선택하지 않는다.

## 실행 결과

구조 정리 후 448개 전체 회귀를 먼저 확인했고, R7-E 통합 후 기존 439개와 신규 114개를 합한 553개가 통과했다. 실패·오류·건너뜀은 0개다. 독립 인수 24개와 최종 독립 검토도 완료했다. [검증 기록](../VALIDATION.md)을 따른다. 다음은 R7-F이며 이번 변경은 로컬 미릴리스다.

## 이후 배포

이 문서의 미릴리스 표시는 구현 당시의 상태다. 사용자 배포 요청에 따라 이 변경을 v0.11.0 사전 릴리스에 포함한다. [릴리스 범위](../releases/v0.11.0.md)를 따른다.
