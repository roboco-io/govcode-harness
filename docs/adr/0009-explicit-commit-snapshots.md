# ADR 0009: 엄격 HEAD 검사와 명시적 commit 스냅샷 분리

상태: 로컬 R1-A·R1-B에 적용 / 날짜: 2026-10-28

## 배경

작업 폴더의 캐시·미추적 파일 때문에 명시한 commit의 검사까지 불가능했던 입력 경계를 분리한다.
동시에 과거 안전 commit을 현재 변경의 통과로 오인하지 않도록 검사 범위를 기록한다.

## 결정

기본 strict_head의 엄격한 HEAD·작업 트리·index 검사는 유지한다.
--commit은 정확한 소문자 40자리 commit SHA를 받으며 그 commit의 Git 객체만 검사한다.
수집 모듈과 원문 없는 snapshot.json을 분리하고 입력 모드를 execution과 도구 지문에 고정한다.
기본 verify는 현재 HEAD와 대조한다. 과거 commit 재검증은 commit_snapshot 증적에 같은 --commit을 명시해야 한다.
결과는 선택한 commit의 판정으로만 해석한다. PR·CI의 예상 commit 대조는 R1-C에서 다룬다.

## 결과와 검증

작업 폴더를 검사하지 않는 경우 worktree_checked=false를 표시한다.
스냅샷의 파일별 지원·미지원·문서·인코딩 상태는 실제 AST 분석 완료와 구분한다.
원문 비저장·commit 고정·미지원·자원 상한·모드 변조·부모 모드·기존 회귀를 검증한다.
현재도 예시 정책과 unsigned 로컬 증적이며 운영 승인을 주장하지 않는다.
