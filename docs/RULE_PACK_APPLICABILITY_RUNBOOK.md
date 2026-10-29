# R7-C/D 규정 팩 발행·잠금·적용성 실행 안내

상태: v0.10.0 사전 릴리스의 R7-A~D 로컬 합성 참조 구현이다.
사업 산출물·요구사항 추적 팩과 개인정보 로깅 연결 팩으로 검증한다. 산출물 검사·요구 충족 평가·단계 게이트·관리 화면 확장은 R7-E 이후다.

## 1. 한 번에 실행

프로젝트 루트에서 기존 참조 환경을 사용한다. 환경 설치는 [참조 실행 안내](REFERENCE_RUNBOOK.md)를 따른다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project pack-demo \
  --output .runtime/my-pack-demo
```

새 전용 폴더에만 자료를 만들며 기존 출력 폴더를 덮어쓰지 않는다. 다음 작업을 실제 서명과 저장소로 실행한다.

1. 합성 작성자·검토자·운영자 키, 승인 프로필 revision 1과 철회 목록 생성.
2. 산출물 추적 팩과 이를 의존하는 개인정보 로깅 팩의 초안·제출·독립 승인·발행.
3. 두 팩의 정확한 버전과 digest를 선택 요청·독립 검토·운영자 서명 잠금본으로 연결.
4. 알려진 참 1개·제외 후보 1개·미확정 1개의 적용성을 판단: 적용 1·제외 0·검토 필요 2.
5. 알려진 거짓 조건의 제외 후보에 독립 서명 검토 적용: 적용 1·제외 1·검토 필요 1.
6. 미확정 정보를 보완한 프로필 revision 2를 독립 승인하고 잠금 순번 2를 발행. 오래된 잠금본과 검토 기록의 재사용 거부.
7. 별도 음성 시험용 팩을 실제 철회하고 새 철회 목록으로 사용 거부 확인.
8. 현재 두 팩과 새 검토 기록으로 재판단: 적용 2·제외 1·검토 필요 0.

정상 데모 종료 코드는 0이며 checks 7개가 모두 true다. 최종 applicability_resolved는 적용 대상 판단이 끝났다는 뜻이다.
requirements_evaluated=false와 operational_approval=false를 유지한다. 어떤 검사 어댑터도 실행하지 않으며 요구사항 충족·법적 준수·병합 가능을 판정하지 않는다.

## 2. 정적 예시 팩 확인

```sh
.runtime/reference-venv/bin/python -m govcode_harness project validate-pack \
  --manifest rule_packs/delivery-trace/manifest.example.json \
  --requirements rule_packs/delivery-trace/requirements.example.json
```

이는 형태·참조·출처 분류·허용된 검사 ID를 확인한다. valid=true여도 approval_status=not_checked다.
원문·승인·서명·유효기간·의존성까지 현재 사용 가능하다는 결과가 아니며 팩을 발행하지 않는다.
정적 팩은 서명되지 않은 예시다. source의 confirmed도 입력한 확인 기록이며 공식 원문 자동 대조를 뜻하지 않는다.

## 3. 현재 잠금본으로 재판단

데모의 revocation-anchor.json에 있는 digest 값을 아래 인수에 넣는다. 실제 CI에서는 이 기준점을 검사 대상 저장소 밖의 보호된 신뢰 설정으로 공급한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project assess-applicability \
  --profile-registry .runtime/my-pack-demo/profile-registry \
  --lock .runtime/my-pack-demo/pack-lock.json \
  --trust .runtime/my-pack-demo/public-trust.json \
  --revocations .runtime/my-pack-demo/revocations.json \
  --expected-revocation-digest '<보호한 anchor의 digest 값>' \
  --min-revocation-epoch 2 --min-sequence 2 --min-profile-revision 2 \
  --tenant-id TENANT-REFERENCE --project-id PROJECT-DELIVERY-REFERENCE \
  --review .runtime/my-pack-demo/applicability-review.json
```

현재 시각은 CLI가 UTC로 읽는다. 과거 시각을 사용자가 지정해 만료를 우회하는 CLI 옵션은 제공하지 않는다.
검토 파일을 생략하면 알려진 거짓 조건도 제외로 확정하지 않으므로 검토 필요 결과가 된다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | 팩 데이터 검증 또는 적용성 판단 완료. 결과 kind·outcome을 함께 확인. gate allow가 아님 |
| 3 | 미확정 정보·자료 누락·적용 제외 검토·법령 적용 검토가 남음 |
| 4 | 서명·범위·digest·순번·만료·철회·계약·조건식 오류. 일부 결과를 사용해 통과시키지 않음 |

데모 철회 목록의 유효기간은 1시간이다. 시간이 지나면 새 목록과 보호된 epoch·digest 기준점이 필요하다.
공개된 결과 파일만 보고 현재 사용 가능하다고 판단하지 말고 원래 서명 증거와 현재 프로필로 다시 검증한다.

## 4. 팩 발행과 잠금의 증거

RulePackRegistry는 프로젝트별 로컬 파일 잠금과 추가 전용 서명 이벤트를 사용한다.

| 작업 | 권한·검증 |
| --- | --- |
| draft·submit | author 서명, 동일 작성자, 불변 팩 ID·버전·내용 digest |
| approve·reject | approver 서명, 작성자와 다른 actor. 키만 달라도 actor가 같으면 자기 승인 |
| publish | operator 서명. 원래 작성·제출·승인 서명과 동일 내용, 출처 확인·강제성·의존성·유효 구간 |
| retire·revoke | operator 서명, 대상 버전·내용 고정. 새 철회 목록에 대상 digest를 유지 |
| 잠금 선택 | author의 전체 선택 요청과 독립 approver의 요청 digest 검토 |
| 잠금 발행 | operator 서명, 현재 승인 프로필·정확한 전체 팩 목록·의존성·검토·순번 |

원문이 미확정인 출처, undetermined 강제성, unverified_requirement 기반 팩은 승인·발행하지 않는다.
초안 수정은 새 버전이다. 발행된 버전의 내용을 덮어쓰거나 자동 latest 선택·만료 시 과거 버전 복귀를 하지 않는다.
동일 ID·버전·내용의 공유 요구는 한 번 집계하고, 다른 내용이나 버전 충돌은 오류다. 같은 팩의 여러 버전을 한 잠금본에 넣지 않는다.
의존성이 빠지거나 순환·digest 불일치·철회가 있으면 전체 잠금본을 거부한다. 검사 명세는 등록된 ID만 참조하며 shell·Python·임의 플러그인·네트워크 설치를 실행하지 않는다.

기존 policy_bundle_refs가 있는 새 잠금본은 아직 사용하지 않는다. 검증하지 않은 구형 정책 참조를 무시하지 않고 명시적 오류로 거부하며, 기존 코드 게이트와의 실제 실행 통합은 후속 단계다.

## 5. 철회·만료·롤백 경계

만료는 팩·발행본·승인·선택 검토·잠금·프로필 승인·적용성 검토·철회 목록 각각에 확인한다.
서명 키는 현재 신뢰 목록의 역할·actor·기관·프로젝트·revoked 값과 철회 목록의 key_ids를 대조한다. 키 발급·KMS·기관 신원·자동 키 수명 관리까지 구현한 것은 아니다.

| 기준 | 역할 |
| --- | --- |
| 저장소 이벤트 sequence | expected_sequence 충돌 검사와 추가 전용 이력 |
| 발행 sequence | 팩별 최소 발행 순번으로 이전 발행본 재사용 방지 |
| 잠금 sequence | 프로젝트 선택 잠금본의 최소 순번 고정 |
| 철회 epoch + 기대 digest | 오래된 목록과 다른 내용의 가짜 높은 순번 목록 거부 |
| 저장소 checkpoint | 저장소 신원·순번·head digest를 묶어 이력 삭제·다른 분기 탐지 |

verify_release·verify_lock·assess에는 보호된 expected_revocation_digest가 필요하다. 받은 비신뢰 목록에서 hash를 계산해 곧바로 ‘기대값’으로 넣으면 이 신뢰 검증을 대신할 수 없다.
검증은 author·approver·operator·선택 작성자·검토자·현재 프로필 승인에 현재 신뢰 정보를 다시 적용한다. 철회는 키뿐 아니라 팩 내용·발행·승인·잠금·검토 기록 digest에도 적용한다.
철회 목록은 누적되고 이전 항목을 제거하지 않는다. 발행자 자신을 철회하는 목록은 사용할 수 없으므로 운영자 키 철회에는 다른 유효한 operator 키가 필요하다.

목록의 최대 1시간 수명은 참조 구현의 신선도 정책이며 법정 기간이 아니다. 오프라인 소비자가 아직 새 철회 목록·보호된 기준점을 받지 않았다면 즉시 철회를 안다고 주장할 수 없다.
호출자는 최신 신뢰 목록과 외부 보호 기준점을 공급해야 한다. 로컬 소유자가 저장소와 기준점을 함께 되돌리는 것을 파일만으로 막지는 못한다.
신뢰 목록에서 과거 서명자 자체를 revoked로 바꾸면 해당 저장소의 현재 재검증도 실패할 수 있다. 무조건 과거 신뢰를 되살려 읽는 복구 경로는 제공하지 않는다.

## 6. 적용성 판단 규칙

evaluate_expression은 조건 계산기이며 승인이나 적용성 결정이 아니다. assess는 원래 잠금 서명과 현재 프로필을 검증한 뒤 사용한다.

| 조건·근거 | 처리 |
| --- | --- |
| 확인한 예시 요구의 조건이 참, 필요한 사실 모두 known | 적용 대상으로 판단 |
| 알려진 조건이 거짓 | 제외 후보. 독립 서명 검토 전에는 pending |
| unknown·missing·not_applicable 사실을 참조 | pending과 정보 확인 안내. false로 변환하지 않음 |
| all/any로 논리 결과가 결정돼도 참조한 미확정 사실이 남음 | 보수적으로 검토 필요 유지 |
| 예시가 아닌 법령·기관 규정 등 | 참 조건이어도 독립된 적용성 검토 필요 |
| 지원하지 않는 연산자·타입 불일치·잘못된 구조 | error. 미분석을 false로 간주하지 않음 |

eq·in·all·any·not만 사용하고 boolean false와 integer 0을 구분한다. not unknown도 unknown이다.
서명 검토로 미확정 사실을 강제로 해소하거나 알려진 조건과 반대 결론을 만들 수 없다. 사실 확인·프로필 개정 또는 팩 조건 개정 후 다시 판단한다.
적용 제외 검토자는 프로필 작성자·팩 작성자·선택 요청자와 다른 actor여야 한다. 검토는 현재 잠금·프로필·요구 digest와 유효 구간에 묶인다.
새 프로필을 승인하거나 잠금·조건을 바꾸면 이전 검토를 재사용할 수 없다. 같은 요구의 중복 검토나 같은 event ID의 다른 검토도 거부한다.

보고서의 total은 선택한 잠금본의 고유 요구 수다. applicable·not_applicable·pending을 모두 표시한다. 전체 법령 목록의 완전성이나 요구 충족률을 뜻하지 않는다.
fact 값·문서 원문 대신 참조 ID·판단 근거 코드·다음 확인 작업을 출력한다. next_actions는 안내이며 R7-F의 작업 완료 상태를 구현한 것은 아니다.

## 7. 라이브러리와 생성 파일

발행 순서는 RulePackRegistry.create → apply(서명 draft/submit/approve) → publish다.
issue_revocations는 누적 철회 목록을 발행하고, publish_lock은 서명 선택 요청·검토와 전체 의존 팩 발행본을 받아 현재 프로필을 확인한다.
verify_release는 한 발행본의 무결성과 현재 유효성을 확인하지만 의존성 완료는 확인하지 않는다. 전체 선택은 verify_lock으로 검증한다.
get은 이력 상태 조회이며 현재 사용 승인 결과가 아니다.

주요 생성 파일은 다음과 같다.

- delivery/ privacy의 manifest·requirements: 서명 전 데이터 원본.
- profile-registry/·pack-registry/: 버전·승인·발행·철회 이력.
- pack-lock.json·applicability-review.json: 현재 잠금본과 독립 제외 검토.
- revocations.json·revocation-anchor.json: 철회 목록과 보호해야 할 기준점.
- applicability-initial.json·applicability-reviewed.json·applicability-final.json: 전후 판단. 과거 결과는 현재 승인 자료가 아님.
- public-trust.json·profile-checkpoint.json·pack-checkpoint.json: 공개키 정보와 상태 기준점.
- private/: 합성 개인 키. 출력 폴더 전체를 Git·이슈·외부 보고서에 올리지 않는다.

초기 상한은 잠금본 64팩, 한 팩 1,000요구, 개별 JSON 1MiB, 저장소 1,000이벤트·16,000,000바이트다.
서명 증거를 함께 넣으므로 바이트 상한이 더 먼저 걸릴 수 있다. 초과 시 일부를 생략하지 않고 오류로 중단한다.

## 8. 검증 명령

```sh
.runtime/reference-venv/bin/python -m unittest \
  tests.test_rule_pack tests.test_applicability tests.test_rule_pack_cli -q
.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
```

기존 전체 시험의 오철칙 전용 환경과 실제 HTTP·OS 격리 준비는 [프로필 실행 안내](PROJECT_PROFILE_RUNBOOK.md)를 따른다.
현재 계약과 다음 단계의 관계는 [R7 상세 명세](PROJECT_PROFILE_RULE_PACK_SPEC.md)를 참고한다.
