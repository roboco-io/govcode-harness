# GovCode Harness

**공공 프로젝트의 법령·규칙·가이드라인을 실행 가능한 요구와 작업으로 연결하는 규정 준수 하네스.**
적용 요구 파악부터 작업 안내, 자동 검사·수정 지원, 담당자 검토·승인·증적까지 충족 과정을 안내하는 것이 제품의 목적이다.

현재 **v0.9.0 로컬 참조 구현**은 첫 Vertical Slice인 민원 API 개인정보 로깅으로 이 흐름의 공통 기반을 검증했다. 다른 규정 분야의 자동 충족 기능은 후속 설계·구현 범위다.
실제 기관 승인·법령 적용 확정·원격 CI 배포·실데이터 파일럿 완료를 뜻하지 않는다.

[온보딩 가이드](https://roboco.io/govcode-harness-guide/onboarding.html) · [브로슈어](https://roboco.io/govcode-harness-guide/brochure.html) · [공개·버전 관리 안내](docs/PUBLICATION.md)

[제품 목적](INTENT.md) · [전체 범위와 후속 설계](docs/PRODUCT_DIRECTION.md)

## 첫 사례 바로 실행

현재 작업 폴더의 참조 환경에서 실행한다. 새 출력 경로를 사용한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness reference-demo --output .runtime/my-reference-demo
```

실제 서명·CI 거부/통과·승인된 합성 수정의 OS 격리 검증·증적 이동·보관·복구·역할별 로컬 API를 확인한다.
모델 backend는 fixture이며 실제 모델 추론·품질은 검증하지 않았다. 격리가 없거나 필수 검증이 미완료면 exit 3이다.
새 환경 설치와 관리 화면 접속은 [참조 실행 안내](docs/REFERENCE_RUNBOOK.md)를 따른다.

## 구현 범위

| 기능 | 상태 |
| --- | --- |
| 스냅샷·명시적 commit·CI 예상 SHA 게이트 | 로컬 구현·검증 |
| Python 분석·평가기 | 제한된 지원 범위와 독립 합성 표본 검증 |
| 정책 승인·Ed25519·만료·철회·예외 | 합성 역할의 참조 구현 |
| 포터블 증적·부모 사슬·보관·hold·백업 복구 | 로컬 서명·일관성·권한 검증 |
| 관리 API·한국어 UI | loopback·역할·기관·프로젝트 분리 |
| 모델 제안·독립 승인·격리 수정·재검사 | 모의 모델 + 실제 OS 격리 검증 |
| 오철칙 | 고정 버전의 선택적 보완 PoC |

[랄프 완료 보고](docs/RALPH_COMPLETION_REPORT.md)에 최종 시험·초기 실패·수정·평가·외부 미완료 조건을 정리했다.

## 기본 실행

추가 참조 의존성이 없는 기본 경로도 유지한다. 프로젝트 디렉터리에서 Python 3.10 이상과 Git을 사용한다.

```sh
python3 -m govcode_harness demo --output .runtime/first-slice
```

검사 오류·미지원·누락·만료·증적 실패를 allow로 바꾸지 않는다.
지정 commit의 통과를 현재 작업 폴더나 PR의 승인으로 해석하지 않는다.
입력 코드는 실행하지 않으며, 모델 수정 실행은 별도 승인·새 sandbox·격리·회귀 검증을 요구한다.
민원 원문·원본 로그·개인 키·비밀을 보고서·프롬프트에 복사하지 않는다.

## 문서

- [참조 실행 안내](docs/REFERENCE_RUNBOOK.md) · [외부 운영 준비](docs/EXTERNAL_READINESS.md)
- [완료 보고](docs/RALPH_COMPLETION_REPORT.md) · [검증 기록](docs/VALIDATION.md) · [독립 검토](docs/REVIEW_LEDGER.md)
- [이후 구현 계획](docs/IMPLEMENTATION_ROADMAP.md) · [MVP 백로그](docs/MVP_BACKLOG.md)
- [PRD](docs/PRD.md) · [아키텍처](docs/ARCHITECTURE.md) · [데이터 모델](docs/DATA_MODEL.md)
- [규정 추적 초안](docs/REGULATORY_TRACEABILITY.md) · [ADR](docs/adr/README.md) · [AGENTS.md](AGENTS.md)
- [기본 로컬 실행](docs/LOCAL_SLICE.md) · [스냅샷/commit 범위](docs/SNAPSHOT_COMMIT_MODE.md) · [오철칙 PoC](docs/IRON_LAWS_POC.md)

## 개발·검증

```sh
.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q
.runtime/reference-venv/bin/python scripts/check_scaffold.py
```

실제 HTTP·OS 격리가 허용되는 환경에서 전체 인수 시험을 수행한다. 현재 전체 참조 검증 플랫폼은 macOS다.
원래 스캐폴드 JSON은 정적 예시이며 실제 실행은 지정한 새 폴더에 생성한다.
공개 코드와 안내 사이트는 [공개 안내](docs/PUBLICATION.md)를 따른다. 실제 기관 운영 배포와 업무 CI 적용은 별도다.
