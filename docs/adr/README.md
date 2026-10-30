# Architecture Decision Records

0001~0006의 상태는 **Proposed**다. 0007~0011은 요청된 로컬 프로토타입과 PoC에 한해 적용한다. 이번 초안의 설계 기준으로 사용하되 기관 승인으로 간주하지 않는다.

| ADR | 결정 |
| --- | --- |
| [0001](0001-hybrid-boundary.md) | 기관 내부 실행 + 선택적 중앙 관리 |
| [0002](0002-deterministic-enforcement.md) | 결정적 집행과 AI 제안 분리 |
| [0003](0003-legal-policy-separation.md) | 법적 의무·통제·실행 정책 분리 |
| [0004](0004-evidence-provenance.md) | 입력 고정, 증적 provenance·보관 검증 |
| [0005](0005-modular-local-first.md) | 모듈형 로컬 실행기부터 구현 |
| [0006](0006-first-slice.md) | 민원 API 개인정보 로깅 위험 Vertical Slice |
| [0007](0007-explicit-local-demo.md) | 명시적 로컬 데모·unsigned 증적 경계 |
| [0008](0008-optional-iron-laws.md) | 고정 오철칙의 선택적 보완 검사 |
| [0009](0009-explicit-commit-snapshots.md) | 엄격 HEAD와 명시적 commit 스냅샷 분리 |
| [0010](0010-reference-authority-and-archives.md) | 참조 권한과 역사적 증적 경계 |
| [0011](0011-limited-model-repair.md) | 제한된 모델 제안·독립 격리 검증 |

- [0012 공공 프로젝트의 규정 충족 안내와 첫 사례 구분](0012-project-compliance-purpose.md)

- [0013 프로필 불변 버전·독립 승인·설치 가능한 계약](0013-project-profile-contracts.md)

- [0014 규정 팩 발행·잠금·적용성과 철회 기준점](0014-rule-pack-lock-applicability.md)

- [0015 AI 친화적 설계 문서 초안과 수동 검토 경계](0015-ai-friendly-document-drafts.md)

- [0016 프로젝트 패키지와 commit 고정 산출물 추적](0016-project-package-and-artifact-traces.md)

- [0017 현재 평가·단계 게이트·새 프로젝트 증적 결합](0017-current-assessment-stage-and-project-evidence.md)
