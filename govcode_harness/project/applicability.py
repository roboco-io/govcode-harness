"""Typed three-valued conditions; condition truth is not a compliance verdict."""
import functools
import json
import re

from .. import security
from . import contracts, profile as profiles, packs


class ApplicabilityError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(condition, code='APPLICABILITY_INVALID'):
    if not condition:
        raise ApplicabilityError(code)


def _guard(function):
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except ApplicabilityError:
            raise
        except (contracts.ContractError, security.SecurityError, profiles.ProfileError, packs.PackError) as error:
            raise ApplicabilityError(error.code) from None
        except Exception:
            raise ApplicabilityError('APPLICABILITY_INVALID') from None
    return wrapped


@_guard
def evaluate_expression(expression, profile):
    """Evaluate all branches and retain every unresolved fact, even if truth is known."""
    expression = contracts.validate_expression(expression)
    profile = contracts.validate(profile)
    _require(profile['kind'] == 'project_profile', 'PROFILE_KIND_INVALID')
    pending, facts, reasons = set(), set(), set()

    def evaluate(node):
        op = node['op']
        if op == 'not':
            value = evaluate(node['arg'])
            return None if value is None else not value
        if op in ('all', 'any'):
            values = [evaluate(arg) for arg in node['args']]
            if op == 'all':
                return False if False in values else (None if None in values else True)
            return True if True in values else (None if None in values else False)
        literals = [node['value']] if op == 'eq' else node['values']
        types = {value['value_type'] for value in literals}
        _require(len(types) == 1, 'EXPRESSION_TYPE_MISMATCH')
        name = node['fact']
        facts.add(name)
        fact = profile['facts'].get(name, {'state': 'missing'})
        if fact['state'] != 'known':
            pending.add(name)
            reasons.add({'unknown': 'FACT_UNKNOWN', 'missing': 'FACT_MISSING',
                         'not_applicable': 'FACT_APPLICABILITY_UNREVIEWED'}[fact['state']])
            return None
        _require(fact['value_type'] in types, 'EXPRESSION_TYPE_MISMATCH')
        return any(fact['value'] == literal['value'] for literal in literals)

    truth = evaluate(expression)
    return dict(truth='unknown' if truth is None else ('true' if truth else 'false'),
                fact_refs=sorted(facts), pending_facts=sorted(pending), reason_codes=sorted(reasons))


@_guard
def review_subject(lock_digest, profile_digest, requirement_ref, tenant_id, project_id):
    """Construct an approval subject, not an approval or verification receipt."""
    _require(type(requirement_ref) is dict and set(requirement_ref)=={'kind','id','version','digest'},'REVIEW_REFERENCE_INVALID')
    _require(requirement_ref['kind']=='requirement_spec','REVIEW_REFERENCE_INVALID')
    for value in (tenant_id,project_id,requirement_ref['id'],requirement_ref['version']):
        security.identifier(value)
    for value in (lock_digest,profile_digest,requirement_ref['digest']):
        _require(type(value) is str and re.fullmatch(r'[a-f0-9]{64}',value) is not None,'DIGEST_INVALID')
    return contracts.digest(dict(schema_version='1',context=security.CONTEXT,tenant_id=tenant_id,project_id=project_id,
        operational_approval=False,lock_digest=lock_digest,profile_digest=profile_digest,requirement_ref=requirement_ref))


@_guard
def assess(lock, profile_registry, trust, now, *, revocations, expected_revocation_digest,
           reviews=(), min_sequence=1, min_revocation_epoch=1, min_pack_sequences=None, min_profile_revision=1):
    """Resolve applicability using original proofs and current profile authority.

    Unknown facts always require information/review. A known false condition is
    only an exclusion candidate until independently signed. No checks are run.
    """
    _require(isinstance(profile_registry,profiles.ProjectProfileRegistry),'PROFILE_AUTHORITY_REQUIRED')
    lock = json.loads(security.canonical(lock))
    trust = json.loads(security.canonical(trust))
    revocations = json.loads(security.canonical(revocations))
    _require(isinstance(reviews,(tuple,list)) and len(reviews)<=1000,'REVIEW_LIMIT')
    reviews = json.loads(security.canonical(list(reviews)))
    tenant_id,project_id = profile_registry.tenant_id,profile_registry.project_id
    verified = packs.verify_lock(lock,trust,tenant_id,project_id,now,revocations=revocations,
        expected_revocation_digest=expected_revocation_digest,profile_registry=profile_registry,
        min_sequence=min_sequence,min_revocation_epoch=min_revocation_epoch,
        min_pack_sequences=min_pack_sequences,min_profile_revision=min_profile_revision)
    revoked = packs.verify_revocations(revocations,trust,tenant_id,project_id,now,
        min_epoch=min_revocation_epoch,expected_digest=expected_revocation_digest)
    common = dict(schema_version='1',context=security.CONTEXT,tenant_id=tenant_id,project_id=project_id,operational_approval=False)
    requirements = {r['id']:r for r in verified['requirements']}
    conditions, references = {}, {}
    for name,requirement in requirements.items():
        conditions[name] = evaluate_expression(requirement['applicability_expr'],verified['profile'])
        references[name] = dict(kind='requirement_spec',id=name,version=requirement['version'],digest=contracts.digest(requirement))
    forbidden = set(verified['pack_authors']) | {verified['profile_author_id'],verified['selection_author_id']}
    reviewed, event_ids = {}, set()
    for envelope in reviews:
        packs._not_revoked(envelope,revoked,'review_digests')
        value = packs._signed(envelope,trust,'approver','applicability_review',tenant_id,project_id,now)
        _require(value['event_id'] not in event_ids,'REVIEW_EVENT_REPLAY')
        event_ids.add(value['event_id'])
        packs._window(value,now)
        packs._within(value,verified['lock'])
        _require(value['actor_id'] not in forbidden,'SELF_APPROVAL')
        _require(contracts.timestamp(value['created_at'])>=contracts.timestamp(lock['payload']['created_at']),'REVIEW_PRECEDES_LOCK')
        name = value['requirement_ref']['id']
        _require(name in requirements and value['requirement_ref']==references[name],'REVIEW_REFERENCE_MISMATCH')
        _require(name not in reviewed,'REVIEW_DUPLICATE')
        _require(value['lock_digest']==verified['lock_digest'] and value['profile_digest']==verified['profile_digest'],'REVIEW_SUBJECT_MISMATCH')
        expected = review_subject(verified['lock_digest'],verified['profile_digest'],references[name],tenant_id,project_id)
        _require(value['subject_digest']==expected,'REVIEW_SUBJECT_MISMATCH')
        condition = conditions[name]
        if value['decision'] != 'review_required':
            _require(not condition['pending_facts'],'REVIEW_CANNOT_RESOLVE_UNKNOWN')
            _require((value['decision']=='applicable' and condition['truth']=='true') or
                     (value['decision']=='not_applicable' and condition['truth']=='false'),'REVIEW_CONTRADICTS_CONDITION')
        reviewed[name] = (value,contracts.digest(envelope))
    decisions, condition_rows, actions = [], [], []
    counts = dict(total=len(requirements),applicable=0,not_applicable=0,pending=0)
    for name in sorted(requirements):
        requirement,condition,reference = requirements[name],conditions[name],references[name]
        review,digest = reviewed.get(name,(None,None))
        result,reason = 'pending','APPLICABILITY_REVIEW_REQUIRED'
        if condition['pending_facts']:
            reason = 'FACT_INFORMATION_REQUIRED'
            for fact_name in condition['pending_facts']:
                fact = verified['profile']['facts'].get(fact_name,{'state':'missing'})
                actions.append(dict(requirement_ref=reference,
                    action={'missing':'provide_fact','unknown':'confirm_fact','not_applicable':'review_applicability'}[fact['state']],
                    fact_ref=fact_name,owner_ref=fact.get('owner_ref',verified['profile']['owner_ref']),
                    owner_role='author',reason_codes=condition['reason_codes']))
        elif review is not None:
            result = 'pending' if review['decision']=='review_required' else review['decision']
            reason = 'MANUAL_REVIEW_PENDING' if result=='pending' else 'INDEPENDENT_APPLICABILITY_REVIEW'
        elif condition['truth']=='true' and requirement['basis_kind']=='example_policy':
            result,reason = 'applicable','APPROVED_EXAMPLE_CONDITION_MET'
        elif condition['truth']=='false':
            reason = 'EXCLUSION_REVIEW_REQUIRED'
        if result=='pending' and not condition['pending_facts']:
            actions.append(dict(requirement_ref=reference,action='review_applicability',fact_ref=None,
                                owner_ref=None,owner_role='approver',reason_codes=[reason]))
        counts[result] += 1
        identity = contracts.digest(dict(lock_digest=verified['lock_digest'],requirement_ref=reference,review_digest=digest))
        decision = dict(common,kind='applicability_decision',id='APP-'+identity[:32],version='1',requirement_ref=reference,
            profile_digest=verified['profile_digest'],pack_digest=sorted(verified['origins'][name])[0],result=result,
            reason_codes=[reason],fact_refs=condition['fact_refs'],reviewer_ref=review['actor_id'] if review else None,
            review_ref=review['event_id'] if review else None)
        decisions.append(contracts.validate(decision))
        condition_rows.append(dict(requirement_ref=reference,**condition))
    review_set = contracts.digest(sorted(contracts.digest(r) for r in reviews))
    identity = contracts.digest(dict(lock_digest=verified['lock_digest'],review_set_digest=review_set,as_of=now,
                                    revocation_digest=expected_revocation_digest))
    report = dict(common,kind='project_applicability_report',id='APPLICABILITY-'+identity[:32],version='1',as_of=now,
        lock_digest=verified['lock_digest'],profile_ref=verified['lock']['profile_ref'],revocation_epoch=revoked['epoch'],
        revocation_digest=expected_revocation_digest,review_set_digest=review_set,
        outcome='review_required' if counts['pending'] else 'applicability_resolved',requirements_evaluated=False,
        counts=counts,conditions=condition_rows,decisions=decisions,next_actions=actions)
    return contracts.validate(report)
