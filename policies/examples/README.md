# 비활성 예시 정책

이 폴더의 정책은 모두 example_policy, draft, enabled=false다. 운영 승인본이 아니다.
Control은 법적 의무를 지원하는 구현 목표이며 coverage=not_implemented다.
묶음의 digest는 미측정 placeholder이고 서명하지 않았다. 현재 그대로 실행·집행할 수 없다.
예시 만료일은 계약 형식 설명용이며 운영 유효기간 제안이 아니다.

로깅 정책만 첫 시험 묶음에 포함했다. 반출·증적 정책 예시는 향후 별도 집행 지점에서 사용한다.
증적 pending 조건 하나만으로 실패·누락 receipt를 모두 처리할 수 없다.
receipt의 모든 비정상 상태 차단은 아키텍처의 필수 gate 불변 조건으로 구현해야 한다.
condition.value는 MVP에서 문자열로 고정한다. 원자료 포함 여부는 정규화된 문자열 true/false로 입력한다.
