# 패키지 설계 경계와 계약 자료

이 디렉터리는 초기 컴포넌트 설계 설명과 기존 JSON Schema 자료를 담는다. 여러 독립 Python 패키지가 설치되는 구조는 아니다.
실행 코드는 govcode_harness에 있고 프로젝트 기능은 govcode_harness/project에 모은다.
기존 catalog·snapshot 스키마는 contracts에 유지한다. 새 프로젝트 스키마는 설치 자료인 govcode_harness/contracts에 있다.
자료를 중복 복사하지 않는다. [구조 안내](../docs/REPOSITORY_STRUCTURE.md)를 따른다.
