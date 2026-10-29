# 전체 목표 완료 심사

심사 기준은 IMPLEMENTATION_ROADMAP.md의 R1-C~R6와 단계별 완료 기준이다.
사용자는 2026-10-29에 완료 범위를 로컬 참조 구현으로 확정했다. 아래 운영 조건은 이번 완료 범위 밖이며 완료로 주장하지 않는다.

| 요구 | 현재 근거 | 전체 범위 판정·남은 조건 |
| --- | --- | --- |
| R1 입력·commit·CI 게이트 | gate.py, ci/reference-signed-gate.sh, 320개 전체 회귀와 실제 서명 CI 실행 | 로컬 확인. 실제 저장소·필수 검사·브랜치 보호 권한 필요 |
| R2 탐지 확대·독립 평가 | detector.py, evaluation.py, R2_CORPUS.md, 고정 dev/holdout 및 새 확인 표본 | 합성 지원 범위 확인. 실제 기관 코드 성능 미검증 |
| R3 규정·승인·예외 | governance.py, security.py, 실제 서명·철회·대상 결합 회귀, REVIEW_LEDGER.md | 참조 기능 확인. REG-LOG-008 공식 적용본·기관 적용 판단, 운영 승인자·키 미확정 |
| R4 이동·보관·복구 | archive.py, evidence_snapshot.py, evidence_store.py, 이동 archive 검증 및 보관·복구 4개 확인 | 로컬 확인. 실제 보존 분류·저장소 내구성·복구 책임 미확정 |
| R5 관리·기관 파일럿 | control_plane.py, 한국어 UI, 실제 HTTP 5개 확인, 화면 검증 | 참조 기능 확인. 실제 기관·역할·기간·정답 표본·성공 기준·운영 책임자 미확정 |
| R6 제한된 AI 수정 | model_gateway.py, patching.py, 실제 OS 격리·재검사 5개 확인 | fixture 제안 확인. 실제 모델 실행 false, 모델·반출 승인·품질 평가 미실시 |
| 인수·회귀·문서·독립 검토 | final-suite.json: 320개, 실패 0·건너뜀 0; RALPH_COMPLETION_REPORT.md; REVIEW_LEDGER.md | 소프트웨어·합성 범위 확인. 기관 보안 승인으로 대체하지 않음 |
| 승인된 완주 범위 | 사용자 답변: “로컬 참조 구현으로 완료 확정” | 로컬 참조 범위 확정. 실제 운영은 미실시 |

시험 근거는 `.runtime/ralph-full/final-suite.json`과 원본 `final-suite.log`다.
실제 전체 참조 결과는 `.runtime/verified-ralph-final/reference-result.json`이다.
최종 시험 명령은 `.runtime/reference-venv/bin/python -m unittest discover -s tests -p 'test_*.py' -q`이며 83.467초에 종료 코드 0이다.
데이터 계약은 check_scaffold.py의 예시 28개·잘못된 계약 8개 거부와 check_runtime_contracts.py의 실제 엔티티 13개·스냅샷 3개로 확인했다.

## 진행에 필요한 입력

로컬 참조 완료 범위가 확정되어 해당 범위의 Ralph 종료 심사를 진행한다.
실제 운영까지 진행하려면 대상 기관·저장소/CI·신원과 키·보존 기준·모델 정보 및 해당 작업 권한이 필요하다.
답변 대기, 합성 서명, 시험 통과를 운영 승인으로 간주하지 않는다.
