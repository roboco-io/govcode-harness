# 데이터 계약

`catalog.schema.json`은 JSON Schema Draft-07의 `$ref`, `definitions`, `oneOf`를 사용한다.
단일 엔티티를 검증하는 entry point는 파일 최상위다. 각 객체에 `kind`를 넣어 구분한다.
런타임 검증기와 의미 제약 검증기는 아직 구현하지 않았다.
정책 승인·서명·참조·시행 구간·기관 간 권한은 스키마만으로 검증되지 않는다.
세부 의미는 [데이터 모델](../../docs/DATA_MODEL.md)을 따른다.
