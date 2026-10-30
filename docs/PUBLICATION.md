# 공개 저장소와 도입 자료

사용자 요청에 따라 본 프로젝트와 가이드를 roboco-io 조직의 별도 공개 저장소로 관리한다.

- 본 프로젝트: https://github.com/roboco-io/govcode-harness
- 온보딩·브로슈어 저장소: https://github.com/roboco-io/govcode-harness-guide
- 안내 사이트: https://roboco.io/govcode-harness-guide/
- 온보딩: https://roboco.io/govcode-harness-guide/onboarding.html
- PDF: https://roboco.io/govcode-harness-guide/downloads/govcode-harness-brochure.pdf

사용자는 서브모듈 없이 독립 저장소와 버전별 링크로 연결하는 방식을 선택했다.
가이드의 첫 기준 코드는 v0.9.0이다. 코드 태그는 고정하고, 문서는 해당 태그의 기능·지원 범위·검증 근거를 설명한다.

공개 대상은 코드·시험·합성 예시·설계 문서·안내 자료다. .runtime의 개인 키·토큰·로컬 설정·실행 환경·생성 증적은 공개하지 않는다. 실제 기관 자료를 포함하지 않는다.

GitHub Pages는 정적 안내 사이트다. 검사기·민원 API·관리 서버를 공개 호스팅하는 작업이 아니다. 실제 기관 운영 승인·원격 CI 집행·실데이터 파일럿은 별도 과제다.

조직의 기존 GitHub Pages 도메인 설정에 따라 최종 사이트 주소는 roboco.io 아래 경로다. github.io 주소도 해당 경로로 연결된다. 조직의 도메인·다른 저장소 설정은 변경하지 않는다.

## 라이선스와 고정 소스

본 프로젝트는 Apache-2.0, 별도 가이드는 CC BY 4.0으로 제공한다. 제3자 라이선스는 각 원래 표시를 유지한다.
원래 v0.9.0 태그는 보존하고 라이선스 파일이 포함된 v0.9.0-apache2 태그를 추가한다. 가이드의 소스 다운로드와 문서 참조는 이 태그를 사용한다. 검사 엔진·시험·정책의 동작은 변경하지 않는다.

## v0.11.0 프로젝트 배포

v0.11.0 사전 릴리스는 구조 정리와 R7-E~I를 포함한다. [릴리스 범위](releases/v0.11.0.md)와 [전체 실행](PROJECT_REFERENCE_RUNBOOK.md)을 따른다. 기존 가이드 v1.0.0과 Pages는 유지하며 이번 배포는 본 프로젝트의 코드·문서·설치 패키지를 공개한다. 기관 운영 서버 배포는 포함하지 않는다.
