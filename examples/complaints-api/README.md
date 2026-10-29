# 합성 민원 API 코드

`before.py`는 요청 본문이 앱 로그로 전달되는 위험 형태를 설명한다.
`after.py`는 서버 생성 요청 ID·작업·결과만 일반 로그에 남기는 수정 방향이다.
두 함수는 같은 응답과 audit 호출을 유지한다. 실제 API 서버나 완전한 감사 로그 구현은 아니다.
audit 어댑터의 필수 필드·접근통제·보유기간은 기관의 기록 분류 검토 뒤 구현한다.

JSON 파일은 **기대 결과 계약 예시**다. 검사기가 생성하거나 서명한 결과가 아니다.
Run과 정책 묶음의 digest·commit은 미측정 placeholder다. Evidence의 파일 digest는 실제 예시 파일 바이트로 계산했다.
manifest_digest도 아래 예시 직렬화 규칙으로 계산했다. provenance_kind=example이며 실제 검사 실행을 증명하지 않는다.
예시 allow Decision은 증적 receipt까지 완료된 최종 gate 승인을 뜻하지 않는다.

예시 manifest digest 계산에서는 manifest_digest, signature_status, receipt_status를 제외한 객체를 사용한다.
키를 정렬하고 UTF-8·ensure_ascii=false·구분자 쉼표와 콜론·공백 없음으로 직렬화해 SHA-256을 계산한다.
이 규칙은 Python 기반 예시의 재현용이다. 운영에서 사용할 언어 간 canonicalization과 서명 규격은 GCH-007에서 확정한다.
