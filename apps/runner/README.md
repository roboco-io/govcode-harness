# 구현 경계

기관 내부 CLI와 CI 실행기를 구현할 자리다. 소스와 묶음·도구 digest를 고정하고 detector→PDP→evidence→gate 흐름을 연결한다. GCH-004~008에서 구현한다.

현재 상태: 이 별도 패키지 경계는 미분리다. 로컬 구현은 저장소 루트의 govcode_harness/에 있다. [아키텍처 명세](../../docs/ARCHITECTURE.md)를 따른다.
