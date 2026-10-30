# R7-A/B 프로젝트 프로필 실행 안내

상태: v0.10.0 사전 릴리스의 R7-A/B 로컬 참조 구현. 팩 발행·잠금·적용성의 후속 구현은 [R7-C/D 실행 안내](RULE_PACK_APPLICABILITY_RUNBOOK.md)를 따른다. 프로젝트 전체 충족 판정은 포함하지 않는다.

## 1. 실행 환경

새 기능은 기존 참조 환경의 cryptography·jsonschema를 사용한다. 새 외부 의존성은 추가하지 않았다.
환경 설치는 [기존 실행 안내](REFERENCE_RUNBOOK.md)를 따른다. 기존 demo·scan·verify·gate의 기본 동작은 유지한다.
프로필 저장소는 POSIX 파일 잠금을 사용한다. 잠금 기능이 없으면 오류로 종료하며 무잠금으로 진행하지 않는다.

## 2. 프로필 정보 검사

프로젝트 루트에서 실행한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project validate-profile \
  --profile tests/fixtures/project-compliance/profile.example.json \
  --require-fact procurement_type
```

예시는 미확정 정보가 있어 종료 코드 3, outcome=review_required다. 잘못된 입력이라는 뜻은 아니다.
valid=true는 형태·기본 의미 검증만 통과했다는 뜻이며 approval_status=not_checked, requirements_evaluated=false다.
확인할 정보가 없으면 종료 코드 0, outcome=validated다. allow나 기관 승인으로 바꾸지 않는다. 입력 오류는 종료 코드 4다.

| 사실 상태 | 입력과 처리 |
| --- | --- |
| known | value_type·value·source_ref 필수. boolean false와 integer 0을 구분 |
| unknown | owner_ref·reason_ref 필수. value를 넣거나 false로 변환할 수 없음 |
| 누락 | read_fact는 state=missing을 반환. require-fact로 요청하면 정보 제공 안내 생성 |
| not_applicable | 근거·담당자·출처가 있는 주장. 요구의 적용 제외로 확정하지 않고 review_applicability 안내 |

facts에는 프로젝트 조건과 불투명 참조 ID만 넣는다. 계약·민원 원문·개인정보를 넣지 않는다. source_refs의 confirmed는 입력한 출처 확인 기록이며 원문을 자동 대조했다는 뜻이 아니다. 원문 확인과 법적 적용 판단은 별도다. 이 입력 형식이 임의 문자열 안의 개인정보까지 자동 탐지하는 것은 아니다.

## 3. 서명·버전·독립 승인 데모

```sh
.runtime/reference-venv/bin/python -m govcode_harness project profile-demo \
  --output .runtime/my-project-profile-demo
```

새 출력 폴더만 허용한다. 다음을 실제로 수행한다.

1. 합성 작성자·검토자 키와 신뢰 목록 생성.
2. revision 1 생성·제출. 작성자에게 승인 역할도 부여된 음성 사례에서 자기 승인을 거부.
3. 다른 actor의 서명으로 revision 1 승인. 미확정 정보는 그대로 유지.
4. revision 2 초안을 만들고 revision 1이 계속 현재 승인본인지 확인.
5. 정보를 확인한 revision 2를 제출·독립 승인하고 revision 1의 불변성을 확인.

정상 결과는 active_revision=2, checks 6개가 모두 true, operational_approval=false다.
프로필 승인과 요구 충족은 다르므로 requirements_evaluated=false를 유지한다.

생성 자료:

- profile-v1.json·profile-v2.json: 불변 프로필 내용.
- registry/: 서명된 동작과 해시 사슬의 저장소.
- public-trust.json: 합성 공개키·역할·범위. 개인 키를 포함하지 않는다.
- checkpoint.json: 저장소 신원·순번·head digest의 기준점.
- profile-demo-result.json: 키·원문 없는 요약.
- private/: 0600 권한의 합성 개인 키. 출력 폴더 전체를 공개하지 않는다.

## 4. 라이브러리 사용과 저장 의미

ProjectProfileRegistry.create(root, tenant_id, project_id, trust)는 새 저장소만 만든다.
apply(signed_action, now)는 서명·신뢰 역할·범위·expected_revision을 검증한 뒤 이벤트 하나를 원자적으로 기록한다.
키와 역할은 서버가 받은 신뢰 목록에서 확인하며 동작 payload의 주장으로 권한을 얻을 수 없다.

| 동작 | 서명 payload | 역할·조건 |
| --- | --- | --- |
| 개정 | kind=profile_action, action=revise, profile, expected_revision | author. 최초 expected_revision=0; 이후 현재 마지막 revision과 일치 |
| 제출 | kind=profile_action, action=submit, 대상 ID·revision·digest | 동일 작성자. 마지막 초안만 제출 가능 |
| 승인·반려 | kind=profile_approval, decision=approve 또는 reject, 대상 ID·revision·digest, reason_ref | approver. 작성자 actor와 달라야 함. 승인에는 not_before·expires_at 필수 |
| 종료·철회 | kind=profile_action, action=retire 또는 revoke, 대상 ID·revision·digest, reason_ref | operator. 동작별 허용 상태에서만 가능 |

모든 동작에는 schema_version·context·기관/프로젝트·actor_id·event_id·created_at·expected_revision·operational_approval=false가 포함된다.
payload는 기존 security.sign으로 서명한다. [계약 예시](../tests/fixtures/project-compliance/contract-set.example.json)에서 정확한 형태를 볼 수 있다.
실제 동작에는 현재 저장소의 대상 digest와 신뢰한 시각을 사용해야 하며 정적 예시 서명·시간을 재사용하지 않는다.

프로필 내용의 lifecycle=draft는 제안 스냅샷의 고정 값이다. 승인 상태는 별도 이벤트에서 계산한다.
상태는 draft → review → approved/rejected이며 approved는 retired/revoked로 전이할 수 있다. 반려 후 수정은 새 revision으로 작성한다.
새 초안·반려본은 기존 승인본을 덮어쓰지 않는다. 새 승인본이 만료·종료·철회되면 더 오래된 승인본으로 자동 복귀하지 않는다.

get·history는 버전 이력을 보여 준다. 현재 유효한 승인본이 필요하면 active(profile_id, now)를 사용한다.
active에는 min_revision과 expected_profile_digest로 호출자의 하한·대상 고정을 추가할 수 있다.
프로필 승인은 미확정 사실의 존재를 없애지 않으며 법령 적용·규정 팩·단계 게이트를 승인하지 않는다.

## 5. 저장소의 범위와 롤백 방지 조건

저장소는 서명 검증, 연속 순번, 같은 읽기 값의 digest, 부모 이벤트 digest, 파일 잠금, 재실행 ID와 개정 충돌 검사를 사용한다.
최대 1,000개 이벤트·합계 16,000,000바이트이며 개별 JSON은 기존 1MiB 상한을 따른다. 초과하면 쓰기 전에 중단한다.
symlink·비정규 파일·알 수 없는 이벤트 이름·시계 역행·위조된 서명은 거부한다.

checkpoint()는 현재 기준점을 반환한다. 다음 열람 때 ProjectProfileRegistry(root, trust, checkpoint=trusted_checkpoint)로 전달하면 삭제된 꼬리와 기준점 이전의 다른 이력을 거부한다.
기준점 이후의 정상 이벤트 추가는 허용한다. 로컬 파일 소유자가 전체 상태와 기준점을 함께 되돌리는 것을 파일만으로 막을 수는 없다. 신뢰 기준점은 별도 보호 경로에 보존해야 한다.
신뢰 목록도 호출자가 최신본을 제공해야 한다. 새 신뢰 목록에서 서명자가 철회되면 현재 검증은 실패한다. 운영 신원·KMS·기관 보존 정책 연동은 구현하지 않았다.

다중 기관 서비스 호출자는 저장소의 tenant_id·project_id를 인증된 요청 범위와 대조해야 한다. R7-G의 HTTP 경로·권한 연동은 아직 추가하지 않았다.

## 6. 공통 계약의 경계

정본은 govcode_harness/contracts/의 네 JSON Schema다. 설치 패키지에도 포함한다. URI는 식별자이며 검증 중 외부 URI를 조회하지 않는다.
project_contracts.validate는 형태·기본 의미, validate_set은 폐쇄된 객체 집합의 ID·버전·digest·범위·검토 대상 결합을 검사한다.
구형 policy_bundle·source 참조는 별도 검증을 마친 호출자가 scoped external_refs descriptor로 제공할 수 있다. descriptor 자체는 서명·권한 증명이 아니다.
계약 예시의 승인·평가·팩은 데이터 형태 예시다. 프로필 외 객체의 실제 서명 승인·발행·적용·평가 엔진을 구현했다는 뜻이 아니다.

R7-C/D의 팩 발행·잠금·적용성은 [실행 안내](RULE_PACK_APPLICABILITY_RUNBOOK.md)를 따르고, R7-E의 이후 개발은 [산출물 실행 안내](ARTIFACT_TRACE_RUNBOOK.md)를 따르고, R7-F~I의 수정·충족 현황·단계 게이트·화면은 [후속 계획](plans/2026-10-29-project-profile-rule-packs.review.md)을 따른다.

## 7. 재현 가능한 시험 준비

새 기능의 집중 시험:

```sh
.runtime/reference-venv/bin/python -m unittest \
  tests.test_project_contracts tests.test_project_profile tests.test_project_cli -q
```

기존 전체 시험을 건너뜀 없이 실행하려면 고정된 선택 도구 환경도 준비한다.

```sh
.runtime/reference-venv/bin/python scripts/setup_iron_laws.py \
  --python .runtime/reference-venv/bin/python --uv /absolute/path/to/uv
.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
```

오철칙 환경 준비는 고정 소스·해시 잠금·별도 실행 환경을 사용한다. 기본 검사에서 오철칙을 자동 활성화하지 않는다.
새 작업 폴더에는 과거 .runtime이 없으므로 기존 폴더·설치를 가정하면 일부 시험이 실패하거나 선택 시험이 건너뛰어질 수 있다.
전체 시험에는 실제 loopback HTTP·macOS 격리 실행 권한도 필요하다. 미지원 환경의 건너뜀을 실행 성공으로 집계하지 않는다.
