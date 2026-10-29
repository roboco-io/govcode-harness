# GovCode Harness

## 보안이 내재화된 개발 하네스

**프로젝트 목적:** 다양한 공공 프로젝트에서 비개발자가 안전하게 바이브 코딩을 할 수 있도록 한다. [의도 문서](INTENT.md)를 제품 설명과 구현 방향의 기준으로 삼습니다.

**개발의 속도와 보안의 신뢰를 함께 설계하세요.**

GovCode Harness는 보안 기준을 개발 과정에서 실행할 수 있도록 **검사 → 수정 지원 → 재검사 → 승인·증적**을 연결하는 오픈소스 프로젝트입니다. 개발 도구와 정책·검토 절차를 연결해, 팀이 다음에 할 일과 판단 근거를 같은 흐름에서 확인하도록 돕습니다.

공공 프로젝트에 적용되는 법령·규칙·가이드라인을 수행 작업과 검증 근거로 연결하는 것이 목표입니다. 개인정보 로깅을 첫 사례로 시작해, 프로젝트별 요구와 분야별 규정 팩으로 확장을 설계하고 있습니다.

> **현재 파일럿 단계입니다.** 합성 자료로 검증한 v0.10.0 로컬 참조 구현을 체험할 수 있습니다. 프로젝트 코드는 **Apache-2.0 조건에 따라 라이선스 비용이나 로열티 없이** 사용할 수 있습니다. 사용 경험과 문서·코드 기여를 환영합니다.

[프로젝트 소개](https://roboco.io/govcode-harness-guide/) · [직접 체험하기](https://roboco.io/govcode-harness-guide/onboarding.html) · [파일럿 피드백 남기기](https://github.com/roboco-io/govcode-harness/issues/new?template=01-feedback.yml) · [기여 안내](CONTRIBUTING.md)

## 팀에 어떤 가치가 있나요?

보안 기준을 알고 있어도 실제 개발 작업과 검토 근거로 연결하기는 어렵습니다. GovCode Harness는 개발자·검토자·프로젝트 책임자가 같은 기준으로 협업하는 흐름을 지향합니다.

| 참여자 | 얻을 수 있는 가치 | 현재 확인할 수 있는 것 |
| --- | --- | --- |
| 개발자 | 탐지 결과에서 다음 행동으로 이어지는 흐름 | 첫 로깅 사례의 위험 탐지·차단·수정·재검사 |
| 보안·검토 담당자 | 어떤 정책으로 검사하고 누가 승인했는지 판단할 근거 | 합성 역할의 독립 정책 승인과 서명 증적 |
| 프로젝트 책임자 | 작업과 검토 이력에 대한 가시성 | 관리 화면의 실행·정책·증적 조회. 전체 요구의 충족 현황 안내는 확장 계획 |

AI는 설명과 수정안을 제안하고, 정책 엔진과 필수 검사가 결과를 판정합니다. 담당자의 승인과 검토 책임을 개발 흐름 안에 둡니다.

## 파일럿에 참여하세요

**가이드를 읽고 의견만 남겨도 참여할 수 있습니다.** 실제 기관 자료나 운영 환경을 준비할 필요는 없습니다.

1. **살펴보기:** [온보딩 가이드](https://roboco.io/govcode-harness-guide/onboarding.html) 또는 [브로슈어](https://roboco.io/govcode-harness-guide/brochure.html)에서 개발 흐름과 지원 범위를 확인하세요.
2. **체험하기:** 아래 합성 데모를 실행하고 위험 코드의 차단, 수정본의 통과, 생성된 증적을 확인하세요.
3. **의견 남기기:** [파일럿 피드백 양식](https://github.com/roboco-io/govcode-harness/issues/new?template=01-feedback.yml)에 도움이 된 점, 막힌 지점, 다음에 필요한 것을 알려 주세요. 버전·환경·시도한 작업을 함께 적으면 검토에 도움이 됩니다.

버그는 [버그 보고](https://github.com/roboco-io/govcode-harness/issues/new?template=02-bug.yml), 새 기능과 문서 개선은 [개선 제안](https://github.com/roboco-io/govcode-harness/issues/new?template=03-improvement.yml)을 이용하세요. 문구 수정과 코드 PR도 환영합니다. 준비·검증 방법은 [기여 안내](CONTRIBUTING.md)에 있습니다.

공개 이슈와 PR에는 합성 예시만 올려 주세요. 개인정보·기관 내부 자료·원본 로그·토큰·개인 키를 포함하지 마세요. 기관 이름과 연락처를 공개할 필요는 없습니다.

## 첫 개발 흐름을 직접 체험하세요

Python 3.10 이상과 Git이 필요합니다. 처음 시작한다면 라이선스 파일이 포함된 고정 태그를 새 폴더에 받으세요. 데모는 추가 Python 패키지 없이 실행할 수 있습니다.

```sh
git clone --branch v0.10.0 --depth 1 https://github.com/roboco-io/govcode-harness.git
cd govcode-harness
python3 -m govcode_harness demo --output .runtime/first-slice
```

데모는 출력 폴더 안에 합성 Git 저장소를 만들고 다음 흐름을 실행합니다.

```text
민원 본문의 일반 로그 기록 → 위험 탐지·차단(deny)
알려진 수정본으로 변경 → 새 commit 재검사 → 통과(allow) → 전후 증적 연결
```

정상 실행 결과에는 `before: deny`, `after: allow`가 표시됩니다. 응답 유지, 일반 로그의 민원 원문 제거, 필요한 감사 호출 보존도 확인합니다. 기본 데모의 증적은 서명되지 않으며 `signature_status: not_signed`로 표시됩니다.

출력 폴더가 이미 있다면 새로운 `--output` 경로를 지정하세요. 데모는 기존 업무 저장소를 수정하지 않습니다.

**서명·승인·관리 화면까지 확인하려면:** [참조 실행 안내](docs/REFERENCE_RUNBOOK.md)에 따라 전용 환경을 준비하세요. 전체 참조 검증 플랫폼은 macOS이며 Python 3.12 이상, Git, uv, OS 격리 실행 환경이 필요합니다. 환경을 준비한 프로젝트 루트에서 실행합니다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness reference-demo --output .runtime/my-reference-demo
```

## R7-A~D 프로젝트 프로필·규정 팩 참조 구현

공통 계약·프로필 버전·독립 승인에 더해, 규정 팩 서명 발행·잠금과 적용성 판단을 추가했습니다. v0.10.0 사전 릴리스에 포함합니다.
[프로필 실행 안내](docs/PROJECT_PROFILE_RUNBOOK.md), [팩·적용성 실행 안내](docs/RULE_PACK_APPLICABILITY_RUNBOOK.md)와 [R7 후속 계획](docs/plans/2026-10-29-project-profile-rule-packs.review.md)을 따릅니다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project profile-demo --output .runtime/my-profile-demo
```

실제 서명으로 두 버전을 승인하고 자기 승인 거부·초안의 기존 승인 보존·미확정 정보와 false의 구분을 확인합니다.
```sh
.runtime/reference-venv/bin/python -m govcode_harness project pack-demo --output .runtime/my-pack-demo
```

서명 팩 발행·의존성 잠금·미확정 정보 검토·독립 제외 승인·재판단·철회 거부를 확인합니다. 적용성 판단 완료는 요구 충족이나 gate allow가 아닙니다. 산출물 검사·충족 평가·새 단계 게이트는 R7-E 이후 범위입니다.

## 지금 확인할 수 있는 범위

현재 v0.10.0은 **제한된 Python 민원 API 로깅 사례, 공통 정책·승인·증적 기반, 프로젝트 프로필·규정 팩·적용성 판단과 문서 초안 생성**을 제공합니다.

| 기능 | 현재 상태 |
| --- | --- |
| 지정 commit 검사·CI 게이트 | 스냅샷과 신뢰한 예상 commit을 대조하는 로컬 구현 |
| Python 로깅 분석·평가 | 제한된 지원 구문과 독립 합성 표본 검증 |
| 정책 승인·서명·만료·철회·예외 | 합성 역할의 참조 구현 |
| 증적 연결·보관 잠금·백업·복구 | 로컬 서명·일관성·권한 검증 |
| 한국어 관리 화면·API | 로컬 접속, 역할·기관·프로젝트별 접근 통제 |
| 수정 제안·승인·격리 검사·재검사 | 모의 모델과 실제 OS 격리를 사용한 참조 흐름 |
| 선택적 오철칙 연동 | 고정 버전의 보완 PoC |

파일럿 단계는 실제 기관 파일럿이나 운영 검증을 완료했다는 의미가 아닙니다. 모델은 모의 응답을 사용하며 실제 LLM의 추론 품질은 검증하지 않았습니다. 참조 흐름은 승인된 제안 수정의 격리 검사와 별도 알려진 수정 commit의 통과를 확인하며, 자동 운영 배포를 수행하지 않습니다.

실제 CI에서 병합·배포를 막으려면 기관 조건에 맞는 연결과 필수 검사 설정이 필요합니다. 운영 민원 요청을 차단하는 기능은 아닙니다. 검사 오류·미지원·누락·만료·증적 실패는 통과로 처리하지 않습니다. 검사 통과는 법적 준수 인증이나 기관 운영 승인을 뜻하지 않습니다.

## 어디로 확장하나요?

프로젝트 프로필로 적용 조건을 정리하고, 분야별 규정 팩으로 요구·작업·산출물·검사·담당자 검토·증적을 연결하는 방향입니다. 개인정보·보안에서 시작해 접근성, 개발 품질, 표준·상호운용성, 사업 산출물, 운영·보존 요구로 확장할 계획입니다.

프로필·규정 팩·적용성 판단은 로컬 참조로 구현했습니다. 분야별 산출물 검사와 충족 평가는 후속 설계·구현 범위입니다. 첫 로깅 사례의 결과를 다른 분야의 검증 결과로 일반화하지 않습니다. [제품 목적](INTENT.md), [전체 범위와 후속 설계](docs/PRODUCT_DIRECTION.md), [구현 계획](docs/IMPLEMENTATION_ROADMAP.md)에서 방향을 확인하고 의견을 보태 주세요.

## 더 자세히 알아보기

| 궁금한 내용 | 안내 |
| --- | --- |
| 설치·실행·관리 화면 | [참조 실행 안내](docs/REFERENCE_RUNBOOK.md) · [기본 로컬 실행](docs/LOCAL_SLICE.md) |
| 검증 결과와 운영 준비 | [완료 보고](docs/RALPH_COMPLETION_REPORT.md) · [검증 기록](docs/VALIDATION.md) · [독립 검토](docs/REVIEW_LEDGER.md) · [외부 운영 준비](docs/EXTERNAL_READINESS.md) |
| 설계와 데이터 계약 | [PRD](docs/PRD.md) · [아키텍처](docs/ARCHITECTURE.md) · [데이터 모델](docs/DATA_MODEL.md) · [ADR](docs/adr/README.md) |
| 규정 근거와 검사 범위 | [규정 추적 초안](docs/REGULATORY_TRACEABILITY.md) · [스냅샷·commit 범위](docs/SNAPSHOT_COMMIT_MODE.md) · [오철칙 PoC](docs/IRON_LAWS_POC.md) |
| 개발·기여·공개 방식 | [기여 안내](CONTRIBUTING.md) · [작업 규칙](AGENTS.md) · [MVP 백로그](docs/MVP_BACKLOG.md) · [공개·버전 관리](docs/PUBLICATION.md) |

## 라이선스와 무상 사용

프로젝트 코드는 [Apache License 2.0](LICENSE) 조건에 따라 **아무 대가 없이 사용할 수 있습니다.** 개인·기관·기업의 상업적 이용·수정·재배포가 가능하며 라이선스 비용이나 로열티를 요구하지 않습니다. 재배포 시 라이선스 사본, 관련 저작권·[NOTICE](NOTICE) 표시, 수정 사실 표시 등 조건을 준수해야 합니다. 라이선스의 무보증 조건이 적용됩니다. 설치·인프라·운영 비용은 사용 환경에 따라 발생할 수 있습니다.

선택적 오철칙 연동의 [기존 MIT 라이선스](integrations/iron-laws/LICENSE)는 유지됩니다. 별도 [가이드·브로슈어](https://github.com/roboco-io/govcode-harness-guide)는 CC BY 4.0입니다.

현재 고정 소스 태그는 `v0.10.0`입니다. 기존 `v0.9.0`과 `v0.9.0-apache2` 태그는 보존합니다. [릴리스 범위](docs/releases/v0.10.0.md)를 확인하세요.

## AI 친화적 설계 문서 초안

[문서 생성 안내](docs/DOCUMENT_GENERATION.md)에 따라 PRD·아키텍처·정책 모델·추적 매트릭스·ADR·백로그 초안을 새 폴더에 생성할 수 있습니다.
행안부 원칙 기반의 작성 정책을 적용하고, 미제공 정보와 수동 검토 항목을 별도로 기록합니다. 문서 생성은 승인이나 준수 인증을 뜻하지 않습니다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project document-kit --output .runtime/design-documents
```
