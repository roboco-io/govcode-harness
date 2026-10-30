"""Current-input requirement assessment; this report is never a stage approval."""
from collections import deque
import json
import re

from .. import security, runtime
from . import applicability, artifact_snapshot, contracts as c, delivery_trace, packs, profile, work_items

REVIEW_FIELDS = {'kind','schema_version','context','tenant_id','project_id','operational_approval',
    'actor_id','event_id','created_at','not_before','expires_at','subject_digest','requirement_ref',
    'artifact_digests','decision','reason_ref'}
SHA = re.compile(r'[a-f0-9]{64}')
STATES = ('satisfied','unsatisfied','review_required','error','not_evaluated','stale')


class AssessmentError(ValueError):
    def __init__(self, code='ASSESSMENT_INVALID'):
        self.code = code
        super().__init__(code)


def _require(condition, code='ASSESSMENT_INVALID'):
    if not condition:
        raise AssessmentError(code)


def _clone(value):
    return json.loads(security.canonical(value))


def _ref(value):
    return dict(kind=value['kind'],id=value['id'],version=value['version'],digest=c.digest(value))


def _tools(lock, requirements, tools):
    if tools is None:
        return None
    tools = _clone(tools)
    _require(type(tools) is dict, 'RESULT_TOOL_AUTHORITY_INVALID')
    declared = {}
    for release in lock['payload']['pack_releases']:
        manifest = release['payload']['author_record']['payload']['manifest']
        for check in manifest['check_specs']:
            declared.setdefault(check['id'],set()).add(check['adapter_id'])
    for requirement in requirements:
        for name in requirement['check_refs']:
            if name in tools:
                _require(type(tools[name]) is dict and len(declared.get(name,set())) == 1 and
                    tools[name].get('adapter_id') in declared[name], 'PACK_CHECK_ADAPTER_MISMATCH')
    return tools


def _reachable(index):
    entities = {v['id']:v for v in index['requirements']+index['artifacts']}
    references = {name:_ref(value) for name,value in entities.items()}
    edges = {name:set() for name in entities}
    for link in index['traces']:
        left,right = link['from_ref'],link['to_ref']
        if link['relation'] != 'depends_on' and left == references.get(left['id']) and right == references.get(right['id']):
            edges[left['id']].add(right['id'])
    result = {}
    for req in index['requirements']:
        found=set();queue=deque([req['id']])
        while queue:
            for target in edges[queue.popleft()]:
                if target not in found:
                    found.add(target);queue.append(target)
        result[req['id']] = found
    return result


def _reviews(envelopes, trust, scope, current, subject, requirements, artifacts, reachable, forbidden, revoked):
    _require(type(envelopes) in (list,tuple) and len(envelopes)<=1000, 'REVIEW_LIMIT')
    envelopes=_clone(list(envelopes))
    result={};events=set()
    for envelope in envelopes:
        _require(c.digest(envelope) not in revoked['review_digests'],'REVIEW_REVOKED')
        value=security.verify(envelope,trust,'approver',*scope)
        _require(set(value)==REVIEW_FIELDS and value['kind']=='project_artifact_review' and
            value['schema_version']=='1' and value['context']==security.CONTEXT and value['operational_approval'] is False,
            'REVIEW_INVALID')
        for key in ('actor_id','event_id','reason_ref'):
            security.identifier(value[key])
        _require(value['actor_id'] not in forbidden,'SELF_APPROVAL')
        _require(value['event_id'] not in events,'REVIEW_EVENT_REPLAY');events.add(value['event_id'])
        _require(c.timestamp(value['not_before'])<=c.timestamp(value['created_at'])<=current<c.timestamp(value['expires_at']),
            'REVIEW_EXPIRED_OR_FUTURE')
        _require(value['subject_digest']==subject,'REVIEW_SUBJECT_MISMATCH')
        reference=value['requirement_ref'];name=reference.get('id') if type(reference) is dict else None
        _require(name in requirements and reference==_ref(requirements[name]),'REVIEW_REFERENCE_MISMATCH')
        _require(name not in result,'REVIEW_DUPLICATE')
        digests=value['artifact_digests']
        expected=sorted({artifacts[k]['content_digest'] for k in reachable[name] if k in artifacts})
        _require(type(digests) is list and digests==expected and bool(expected) and
            all(type(d) is str and SHA.fullmatch(d) for d in digests),'REVIEW_ARTIFACT_MISMATCH')
        _require(value['decision'] in ('approved','rejected','review_required'),'REVIEW_DECISION_INVALID')
        result[name]=(value,c.digest(envelope))
    return result,envelopes


def assess(repo,commit,index_path,profile_registry,lock,trust,now,*,revocations,expected_revocation_digest,
           applicability_reviews=(),result_receipts=(),result_tools=None,reviews=(),min_sequence=1,
           min_revocation_epoch=1,min_profile_revision=1):
    """Reverify originals, capture once, derive a full denominator and current work.

    The signed reviewer declares content acceptance. This software does not infer
    that declaration from document wording and does not grant a stage approval.
    """
    try:
        _require(isinstance(profile_registry,profile.ProjectProfileRegistry),'PROFILE_AUTHORITY_REQUIRED')
        current=c.timestamp(now)
        lock,trust,revocations=_clone(lock),_clone(trust),_clone(revocations)
        for sequence in (applicability_reviews,result_receipts,reviews):
            _require(type(sequence) in (list,tuple) and len(sequence)<=1000,'REVIEW_LIMIT')
        applicability_reviews,result_receipts,reviews=(_clone(list(sequence)) for sequence in (applicability_reviews,result_receipts,reviews))
        scope=(profile_registry.tenant_id,profile_registry.project_id)
        kwargs=dict(revocations=revocations,expected_revocation_digest=expected_revocation_digest,
            min_sequence=min_sequence,min_revocation_epoch=min_revocation_epoch,min_profile_revision=min_profile_revision)
        verified=packs.verify_lock(lock,trust,*scope,now,profile_registry=profile_registry,**kwargs)
        app=applicability.assess(lock,profile_registry,trust,now,reviews=applicability_reviews,**kwargs)
        revoked=packs.verify_revocations(revocations,trust,*scope,now,min_epoch=min_revocation_epoch,
            expected_digest=expected_revocation_digest)
        for key in revoked['key_ids']:
            if key in trust['keys']:
                trust['keys'][key]['revoked']=True
        required=verified['requirements'];requirements={r['id']:r for r in required}
        tools=_tools(lock,required,result_tools)
        captured=artifact_snapshot.collect(repo,commit,index_path,tenant_id=scope[0],project_id=scope[1])
        inspection=delivery_trace.inspect(captured,now=now,expected_requirements=required,result_receipts=result_receipts,
            trust=trust,allowed_result_tools=tools)
        common=dict(schema_version='1',context=security.CONTEXT,tenant_id=scope[0],project_id=scope[1],operational_approval=False)
        subject_inputs=dict(common,commit_sha=commit,profile_digest=verified['profile_digest'],lock_digest=verified['lock_digest'],
            artifact_manifest_digest=inspection['artifact_manifest_digest'],tool_digest=runtime._tool_digest())
        subject=c.evaluation_subject(subject_inputs)
        reachable=_reachable(captured['index'])
        artifacts={a['id']:a for a in captured['index']['artifacts']}
        forbidden=set(verified['pack_authors'])|{verified['profile_author_id'],verified['selection_author_id']}
        # The current index has no independently authenticated document-author
        # field. Keep local-reference authors and approvers separate by actor,
        # including a different key for an actor holding the author role.
        forbidden.update(key['actor_id'] for key in trust['keys'].values()
            if (key.get('tenant_id'),key.get('project_id'))==scope and 'author' in key.get('roles',[]))
        reviewed,review_envelopes=_reviews(reviews,trust,scope,current,subject,requirements,artifacts,reachable,forbidden,revoked)
        decisions={r['requirement_ref']['id']:r for r in app['decisions']}
        stage=verified['profile']['stage'];rows=[]
        # Invalid references, payloads and signatures are input errors even if an
        # implicated requirement is excluded or is not yet due.
        error_codes={f['code'] for f in inspection['findings'] if f['code'] in {
            'TRACE_REFERENCE_INVALID','TRACE_EDGE_DUPLICATE','TRACE_RELATION_INVALID','TRACE_DEPENDENCY_CYCLE',
            'TEST_ATTESTATION_INVALID','RESULT_TOOL_AUTHORITY_INVALID','RESULT_TRUST_INVALID','RESULT_RECEIPTS_INVALID',
            'ARTIFACT_JSON_INVALID'}}
        if any(check['status']=='error' for check in inspection['checks']) and not error_codes:
            error_codes.add('UNCLASSIFIED_INSPECTION_ERROR')
        for name in sorted(requirements):
            requirement=requirements[name];decision=decisions[name];applies=decision['result']
            relevant={name}|reachable[name]
            findings=[f for f in inspection['findings'] if f.get('entity_id') in relevant or f.get('entity_id') is None]
            codes={f['code'] for f in findings}
            related_review=reviewed.get(name)
            check_results=[]
            if applies=='pending':status='review_required';codes.update(decision['reason_codes'])
            elif applies=='not_applicable':status='not_applicable';codes=set(decision['reason_codes'])
            elif stage not in requirement['stages']:status='not_due';codes={'NOT_DUE_IN_APPROVED_STAGE'}
            else:
                codes.update(error_codes)
                bycheck={check:[] for check in delivery_trace.CHECKS}
                for f in findings:bycheck[f['check_id']].append(f['code'])
                hard_fail={'TRACE_CHAIN_INCOMPLETE','REQUIRED_ARTIFACT_MISSING','REQUIRED_ARTIFACT_TRACE_INCOMPLETE',
                    'ARTIFACT_EMPTY','MARKDOWN_STRUCTURE_INVALID','JSON_DOCUMENT_STRUCTURE_INVALID','TEST_EXECUTION_FAILED'}
                unsupported={'ARTIFACT_UNSUPPORTED','ARTIFACT_ENCODING_UNSUPPORTED','MARKDOWN_HTML_UNSUPPORTED'}
                missing={'TEST_ATTESTATION_REQUIRED','NO_TRUSTED_TEST_CHECK','RESULT_TOOL_AUTHORITY_NOT_PROVIDED','RESULT_TRUST_NOT_PROVIDED'}
                for check,values in bycheck.items():
                    value_set=set(values)
                    check_status='error' if error_codes else ('fail' if value_set&hard_fail else
                        ('review_required' if value_set&(unsupported|missing) else 'pass'))
                    check_results.append(dict(check_id=check,status=check_status,reason_codes=sorted(value_set)))
                if error_codes:status='error'
                elif codes&hard_fail:status='unsatisfied'
                elif codes&unsupported:status='review_required'
                elif codes&missing:status='not_evaluated'
                elif related_review and related_review[0]['decision']=='rejected':status='unsatisfied';codes.add('ARTIFACT_REVIEW_REJECTED')
                elif requirement['review_required'] and (not related_review or related_review[0]['decision']!='approved'):
                    status='review_required';codes.add('ARTIFACT_REVIEW_REQUIRED')
                elif related_review and related_review[0]['decision']=='review_required':
                    status='review_required';codes.add('ARTIFACT_REVIEW_PENDING')
                else:status='satisfied'
            rows.append(dict(requirement_ref=_ref(requirement),applicability=applies,status=status,
                artifact_digests=sorted({artifacts[k]['content_digest'] for k in reachable[name] if k in artifacts}),
                check_results=check_results,review_refs=[related_review[1]] if related_review else [],reason_codes=sorted(codes)))
        counts=dict(total=len(rows),applicable=app['counts']['applicable'],not_applicable=app['counts']['not_applicable'],
            pending=app['counts']['pending'],current=sum(r['applicability']=='applicable' and stage in requirements[r['requirement_ref']['id']]['stages'] for r in rows),
            not_due=sum(r['status']=='not_due' for r in rows))
        counts.update({state:sum(r['status']==state for r in rows) for state in STATES})
        _require(counts['total']==counts['applicable']+counts['not_applicable']+counts['pending'],'ASSESSMENT_COUNTS_INVALID')
        _require(counts['applicable']==counts['current']+counts['not_due'],'ASSESSMENT_COUNTS_INVALID')
        outcome=('error' if error_codes or counts['error'] else ('review_required' if counts['pending'] or any(counts[s] for s in ('review_required','not_evaluated','stale'))
            else ('deny' if counts['unsatisfied'] else 'ready_for_stage')))
        report=dict(common,kind='project_assessment_report',stage=stage,**{k:v for k,v in subject_inputs.items() if k not in common},
            profile_ref=verified['lock']['profile_ref'],subject_digest=subject,input_mode='commit_snapshot',worktree_checked=False,
            requirements_evaluated=True,stage_gate_evaluated=False,applicability_digest=c.digest(app['decisions']),
            revocation_digest=expected_revocation_digest,revocation_epoch=revoked['epoch'],
            result_set_digest=c.digest(sorted(c.digest(r) for r in result_receipts)),result_tools_digest=c.digest(tools),
            review_set_digest=c.digest(sorted(c.digest(r) for r in review_envelopes)),requirements=rows,counts=counts,
            outcome=outcome,reason_codes=sorted(error_codes))
        report['work_items']=work_items.plan(report,verified['profile']['owner_ref'])
        report['evaluation_digest']=c.digest(report)
        return _clone(report)
    except AssessmentError:
        raise
    except (security.SecurityError,c.ContractError,packs.PackError,profile.ProfileError,
            applicability.ApplicabilityError,artifact_snapshot.ArtifactSnapshotError,delivery_trace.DeliveryTraceError) as error:
        raise AssessmentError(error.code) from None
    except Exception:
        raise AssessmentError('ASSESSMENT_INVALID') from None
