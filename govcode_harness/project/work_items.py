"""Deterministic source-free next actions; no task is marked complete by AI."""
from .. import security
from . import contracts as c

ACTIONS = {
    'pending': ('confirm_applicability', '프로젝트 조건과 적용 근거를 확인하고 독립 검토를 요청한다.'),
    'not_evaluated': ('run_required_checks', '현재 입력에서 필수 검사를 실행하고 서명한 결과를 연결한다.'),
    'review_required': ('request_independent_review', '필요한 자료를 확인하고 현재 산출물에 대한 독립 검토를 요청한다.'),
    'unsatisfied': ('repair_and_recheck', '누락되거나 실패한 항목을 보완하고 새 commit에서 다시 검사한다.'),
    'error': ('resolve_verification_error', '검증 오류를 해결하고 신뢰한 입력으로 다시 검사한다.'),
    'stale': ('refresh_current_inputs', '변경된 현재 입력으로 검사와 독립 검토를 다시 수행한다.'),
}


def plan(report, owner_ref):
    """Return stable, scoped work descriptions without source text or completion."""
    security.identifier(owner_ref)
    result = []
    for row in report['requirements']:
        key = 'pending' if row['applicability'] == 'pending' else row['status']
        if key not in ACTIONS:
            continue
        action, instruction = ACTIONS[key]
        identity = dict(requirement_ref=row['requirement_ref'], action=action,
                        subject_digest=report['subject_digest'])
        result.append(dict(kind='project_work_item', id='WORK-'+c.digest(identity)[:32],
            tenant_id=report['tenant_id'], project_id=report['project_id'], requirement_ref=row['requirement_ref'],
            subject_digest=report['subject_digest'], action=action, instruction=instruction,
            owner_ref=owner_ref, owner_role='author', status='open', reason_codes=row['reason_codes']))
    return sorted(result, key=lambda value: value['id'])
