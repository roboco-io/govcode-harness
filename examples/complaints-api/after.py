"""합성 수정 예시. request_id는 서버가 생성한 불투명 ID여야 한다."""

def submit_complaint(request_body, request_id, logger, audit):
    logger.info("complaint_received", extra={
        "request_id": request_id,
        "operation": "complaint_submit",
        "result_code": "received",
    })
    # 본문 제외가 필수 감사 기록 삭제로 이어지면 안 된다.
    audit.record_event("complaint_received", request_id=request_id)
    return {"status": "received", "request_id": request_id}
