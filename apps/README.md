# 앱 설계 경계

이 디렉터리는 초기 runner와 control-plane의 설계 설명을 담는다. 현재 독립 실행 패키지가 아니다.
실제 CLI는 govcode_harness/__main__.py, 기존 관리 API는 govcode_harness/control_plane.py와 ui에 있다.
프로젝트 기능의 실제 코드는 govcode_harness/project에 있다. [구조 안내](../docs/REPOSITORY_STRUCTURE.md)를 따른다.
