# AI 친화적 설계 문서 생성 안내

## 목적과 적용 범위

하네스는 설계 문서 초안을 생성할 때 [작성 정책](../govcode_harness/document_assets/DOCUMENT_WRITING_POLICY.md)을 적용한다.
정책은 [AI Doc Ready 작성 지침](https://roboco.io/aidocready/manual.html#writing-instructions)의 행안부 원칙과 보완 지침을 구분한다.
이 원칙을 법적 의무나 기관별 의무로 자동 승격하지 않는다. 코드·설정·일반 대화에는 문서 형식을 강제하지 않는다.
기존 설계 문서와 다른 저장소는 이 명령으로 일괄 변환하지 않는다.

## 초안 생성

프로젝트 루트에서 다음 명령을 실행한다. 출력 폴더는 새 경로여야 한다.

```sh
.runtime/reference-venv/bin/python -m govcode_harness project document-kit --output .runtime/design-documents
```

명령은 PRD, 아키텍처 명세, 정책·통제 데이터 모델, 규정 추적 매트릭스, ADR, 백로그, AGENTS.md와 작성 정책을 생성한다.
서술형 문단과 일관된 제목 단계를 사용한다. 비교표에는 위쪽에 번호와 제목을 둔다. 불필요한 장식과 중첩 표를 생성하지 않는다.
정보가 없으면 미제공으로 표시한다. 명령의 종료 코드 0은 파일 생성 성공이며, 승인이나 검사 통과를 뜻하지 않는다.

목적·독자·근거와 절별 원문을 제공하려면 다음 형식의 JSON 파일을 준비한다. 실제 기관 자료는 승인된 로컬 환경에서만 사용한다.
아래 내용은 합성 예시다.

```json
{
  "project_name": "합성 사업",
  "purpose": "담당자는 사업 산출물과 요구사항의 연결을 검토한다.",
  "audience": "설계 담당자와 독립 검토자",
  "sources": ["SRC-EXAMPLE: 합성 요구사항 원문. 법령 근거가 아니다."],
  "sections": {
    "PRD": {
      "배경과 목적": "담당자는 승인된 요구사항별로 산출물과 검증 결과를 연결한다."
    }
  }
}
```

```sh
.runtime/reference-venv/bin/python -m govcode_harness project document-kit --context context.json --output .runtime/design-with-context
```

지원 문서 키는 PRD, ARCHITECTURE, DATA_MODEL, TRACEABILITY, ADR, BACKLOG다.
절 이름은 생성된 초안의 제목과 일치해야 한다. 알 수 없는 속성과 절은 거부한다.
입력은 일반 텍스트로 취급하며 Markdown 제어 문자를 이스케이프한다. 임의 지시나 명령을 실행하지 않는다.
근거를 제공해도 출처의 권위와 법적 적용성을 자동 확인하지 않는다.

## 구조 검사와 수동 검토

AI Doc Ready 0.3.0은 선택적으로 설치한다. 이 명령은 npm에서 패키지를 내려받으므로 승인된 네트워크 환경에서 실행한다.
하네스의 문서 생성 명령은 외부 프로그램을 자동 설치하거나 실행하지 않는다.

```sh
npm install --prefix .runtime/aidocready --ignore-scripts --no-audit --no-fund --save-exact aidocready@0.3.0
.runtime/aidocready/node_modules/.bin/aidocready lint .runtime/design-documents --format json --fail-on Warning --output .runtime/design-lint.json
```

검토자는 JSON의 진단, checks, coverage와 parserWarnings를 확인한다. 미지원·누락은 검토 필요 상태로 남긴다.
검토자는 사실·수치·단위·날짜·주체·조건·의미를 원문과 대조한다. 표·그림의 적절성과 서술의 명확성도 확인한다.
수정한 문서는 다시 검사한다. HWPX로 변환하면 변환한 파일도 다시 검사하고 병합·캡션 위치를 사람이 확인한다.

review.json은 문서별 SHA-256, 입력 digest와 미수행·수동 검토 항목을 별도로 기록한다.
문서 수정 후 초기 digest는 현재 문서의 검증 결과가 아니다. 최신 검사 결과와 독립 검토 기록을 별도로 보관한다.
이 파일은 서명 승인 증적이나 규정 팩의 검사 결과가 아니다. R7-E/F 산출물 검사·수정 제안과 연결하는 작업은 남아 있다.
작성 정책 적용과 구조 검사 통과를 사실 정확성 보증 또는 행안부 공식 인증으로 표시하지 않는다.
