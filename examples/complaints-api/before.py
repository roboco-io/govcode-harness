"""합성 위험 코드. 실제 서버·운영 입력·실행된 API가 아니다."""

def submit_complaint(request_body, request_id, logger, audit):
    logger.info("complaint=%s", request_body)
    # 필수 감사 기록은 일반 앱 로그와 별도의 승인된 경로로 처리한다.
    audit.record_event("complaint_received", request_id=request_id)
    return {"status": "received", "request_id": request_id}
