# 산출물·요구사항 추적 검사 실행 안내

## 목적과 현재 범위

R7-E는 지정한 Git commit의 JSON·Markdown 산출물을 캡처하고 요구→설계→시험 계획→시험 결과→검토 기록의 연결을 검사한다.
문서 전용 검사는 기존 Python 코드 검사를 대체하지 않는다. 구조·추적·서명 검사가 성공해도 요구 충족이나 단계 통과를 확정하지 않는다.
[저장소 구조](REPOSITORY_STRUCTURE.md), [프로젝트 명세](PROJECT_PROFILE_RULE_PACK_SPEC.md)와 [작성 정책](../govcode_harness/document_assets/DOCUMENT_WRITING_POLICY.md)을 따른다.
v0.11.0 사전 릴리스에 포함한다. 실제 기관 운영 적용은 수행하지 않았다.

## 합성 예시 실행

참조 환경을 준비한 프로젝트 루트에서 새 출력 경로를 사용한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project artifact-demo --output .runtime/my-artifact-demo
```

명령은 새 합성 Git 저장소를 만들고 다음 순서를 실행한다.

1. 작성한 합성 덧셈 시험을 실행하고 시험 결과 파일을 만든다. 제출된 코드나 문서의 지시는 실행하지 않는다.
2. 시험 계획과 시험 결과의 연결이 빠진 commit에서 누락을 찾는다.
3. 연결을 수정한 새 commit을 만들고 문서를 다시 캡처한다.
4. 서명 없는 결과를 검증 성공으로 처리하지 않는지 확인한다.
5. 신뢰 목록의 합성 operator가 현재 commit·산출물·검사 도구에 묶은 별도 실행 증명을 서명하고 검증한다.
6. 과거 commit의 증명이 새 commit에서 거부되는지 확인한다.

출력의 checks는 데모의 인수 결과다. 데모 명령의 종료 코드 0은 시나리오 검증 성공이다.
after-report.json은 요구 출처의 서명 팩을 연결하지 않았으므로 requirement_authority=not_checked와 review_required를 유지한다.
독립 내용 검토와 요구 충족 판정은 남아 있다. 생성된 private 폴더는 로컬 개발 키이며 공개하거나 운영 키로 사용하지 않는다.

## 기존 저장소의 명시적 commit 검사

다음 경로와 commit SHA를 실제 준비한 로컬 합성 저장소 값으로 바꾼다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project inspect-artifacts \
  --repo /path/to/synthetic-repo \
  --commit FULL_40_CHARACTER_COMMIT_SHA \
  --index artifacts.json \
  --tenant-id TENANT-REFERENCE \
  --project-id PROJECT-ARTIFACT-REFERENCE
```

검사는 전체 파일 목록을 고정하고 등록한 산출물의 같은 바이트로 digest와 구조를 확인한다.
현재 작업 폴더의 dirty·staged·미추적 파일은 검사하지 않는다. 출력은 input_mode=commit_snapshot, worktree_checked=false로 범위를 표시한다.
문서 안의 링크를 조회하거나 HTML·스크립트·명령을 실행하지 않는다. 인덱스와 등록 산출물은 commit 안에 있어야 한다.

인덱스의 닫힌 최상위 필드는 kind=project_artifact_index, schema_version=1, context=synthetic_reference,
operational_approval=false, tenant_id, project_id, requirements, artifacts, traces다.
requirement_spec·artifact_ref·trace_link는 기존 프로젝트 계약을 사용한다. 산출물 ID와 경로는 고유하며 인덱스 자신을 산출물로 등록할 수 없다.
JSON은 UTF-8이며 중복 속성·비표준 숫자를 거부한다. 현재 지원하는 문서 형식은 Markdown과 JSON이다.

표 1. 허용하는 추적 방향

| 출발 | 도착 | 관계 |
| --- | --- | --- |
| 요구 | 설계 | implements |
| 설계 | 시험 계획 | verifies |
| 시험 계획 | 시험 결과 | reports |
| 시험 결과 | 검토 기록 | reviews |
| 같은 종류의 항목 | 같은 종류의 항목 | depends_on. 순환은 거부한다. |

각 요구는 검토 기록까지 이어지는 경로가 있어야 한다. 필수 산출물도 해당 요구에서 도달하고 검토 기록까지 이어져야 한다.
다른 정상 경로가 있다는 이유로 별도 필수 산출물의 끊긴 시험·검토 연결을 생략하지 않는다.
Markdown 검사는 첫 제목·제목 단계·코드 블록 등의 제한된 구조 검사다. 원시 HTML과 미지원 문서는 검토 필요로 남긴다.
서술의 적절성·사실·수치·표·그림은 원문 대조와 필요한 AI Doc Ready 검사 및 사람의 검토가 필요하다.

## 서명 규정 팩과 검사 도구 연결

다음 선택 인수는 기존 [팩·적용성 실행 안내](RULE_PACK_APPLICABILITY_RUNBOOK.md)의 현재 승인본을 사용한다.

- --profile-registry, --lock, --trust, --revocations, --expected-revocation-digest를 함께 제공한다.
- --profile-checkpoint는 외부에서 보호한 프로필 기준점을 제공한다.
- --min-sequence, --min-revocation-epoch, --min-profile-revision은 외부에서 보호한 최소 버전을 제공한다.
- --result-tools는 check_id별 adapter_id·tool_digest의 신뢰한 외부 JSON 설정을 제공한다.
- --result-receipt는 별도 서명한 시험 실행 증명 파일을 반복 지정한다.

서명 팩·잠금·현재 프로필·만료·철회 목록을 원본 증명으로 다시 검증한다. 인덱스의 요구 집합을 검증한 팩 전체와 정확히 대조한다.
출처를 검증하지 않은 인덱스가 요구를 삭제해 분모를 줄이거나 자신을 승인할 수 없다.
외부 검사 도구 설정은 서명 팩의 check_specs와 일치해야 한다. 같은 check_id에 서로 다른 어댑터가 있으면 임의 선택하지 않는다.
신뢰 목록·철회 목록 digest·도구 설정·최소 버전은 검사 대상 checkout 밖에서 보호한다. 자기 파일의 해시를 신뢰 기준으로 사용하지 않는다.
프로필·팩·적용성은 서로 다른 결과다. 이 명령은 적용성 재판단이나 단계별 요구 집계를 수행하지 않는다.

## 시험 실행 증명과 검토 기록

시험 결과 파일의 passed·pass 문구는 신뢰 근거가 아니다. 별도의 artifact_test_attestation 서명을 확인한다.
증명은 operator 역할, 기관·프로젝트, 현재 commit, 산출물 manifest, 요구, 결과 산출물, check_id, adapter_id,
tool_digest, 유효 구간과 실제 결과에 결합한다. 다른 대상·도구·서명·만료·철회 키·중복 증명은 거부한다.
실행 증명은 commit 밖에서 서명하므로 자신의 서명을 포함한 commit을 다시 요구하는 순환을 만들지 않는다.
검토 기록 파일은 구조상 연결 대상이다. 문서의 ‘승인’ 문구를 독립 검토자의 승인으로 인정하지 않는다.
현재 신뢰 키의 최신성과 철회 전파는 도입자가 관리한다. 개별 실행 증명의 운영 철회 서비스와 실제 시험 어댑터 연결은 이번 범위가 아니다.

표 2. 검사 결과와 종료 코드

| 결과 | 종료 코드 | 의미 |
| --- | --- | --- |
| checks_passed | 0 | 이 명령의 구조·추적·시험 증명 검사 성공. 요구 충족·gate allow가 아니다. |
| defects_found | 2 | 확정한 추적·구조·시험 실패가 있다. |
| review_required | 3 | 출처·실행 증명·지원 범위 등에 검토가 필요하다. |
| error | 4 | 입력·범위·서명·대상·도구 검증 오류가 있다. |

여러 사유가 있으면 error→review_required→defects_found→checks_passed 순으로 결과를 정한다. 확정 결함도 findings에서 숨기지 않는다.
보고서에는 ID·digest·사유·다음 확인 항목만 기록하고 원문은 포함하지 않는다. 이 보고서는 서명 증적이나 재사용 가능한 게이트 승인본이 아니다.

## 상한과 이후 작업

초기 상한은 전체 Git 파일 100개, 파일당 256,000바이트, 총 2,000,000바이트다. 인덱스의 요구는 1,000개, 추적은 10,000개 이하다.
JSON의 기존 canonical 1MiB·깊이 제한도 적용한다. 상한 초과를 일부 검사 성공으로 처리하지 않는다.
이 상한은 로컬 참조 구현의 자원 정책이며 법정 기준이 아니다. 큰 저장소의 부분 검사 지원은 별도 설계·시험이 필요하다.
R7-F~I의 이후 로컬 구현은 [전체 실행 안내](PROJECT_REFERENCE_RUNBOOK.md)를 따른다. 단독 산출물 검사와 요구 충족·현재 단계 통과는 계속 구분한다.
