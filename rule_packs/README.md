# 분야별 규정 팩 예시

이 폴더는 **서명되지 않은 합성 예시 데이터**다. 실제 법령·기관 규정·계약을 확정하거나 운영 집행을 승인한 자료가 아니다.

| 팩 | 예시 요구 | 의존성 |
| --- | --- | --- |
| delivery-trace | 웹·계약 방식에 따른 산출물 추적 요구의 적용 조건 | 없음 |
| privacy-logging | 개인정보 처리 조건에 따른 로깅 재검사 요구 | delivery-trace의 고정 버전·digest |

manifest.example.json은 출처·요구·등록 검사 ID·유효 구간을, requirements.example.json은 조건·강제성·검토 필요를 정의한다.
source.example.json은 canonical JSON의 SHA-256을 사용한 합성 출처다. confirmed 표시는 이 예시의 확인 기록이다.
어떤 검사 어댑터도 이 데이터만으로 실행되지 않는다.

[R7-C/D 실행 안내](../docs/RULE_PACK_APPLICABILITY_RUNBOOK.md)의 pack-demo는 현재 시각에 맞춘 새 예시를 만들고 실제 서명 발행·잠금·적용성 검토·철회 검증을 수행한다.
