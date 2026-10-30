"""Current local-reference stage decisions over freshly verified original inputs.

A ready candidate is not approval. Release additionally needs the independently
verified, stored R7-H receipt for precisely this candidate.
"""
import re
from pathlib import PurePosixPath

from .. import gate, runtime, security, snapshot
from . import assessment, contracts as c, packs

_CODE_SUFFIXES = frozenset(('.py','.pyw','.js','.jsx','.mjs','.cjs','.ts','.tsx','.java','.go',
    '.c','.h','.cc','.cpp','.cxx','.hpp','.cs','.fs','.vb','.rb','.php','.rs','.swift','.kt','.kts',
    '.scala','.sh','.bash','.zsh','.ps1','.sql','.vue','.svelte','.dart','.ex','.exs','.erl','.clj',
    '.cljs','.lua','.r','.jl','.m','.mm','.pl','.pm','.groovy','.html','.htm','.css','.scss','.sass','.less'))
_RANK = {'ready_for_evidence':0,'deny':1,'review_required':2,'error':3}
_CONTEXT_FIELDS = {'bundle','min_sequence','revocations','exceptions','with_iron_laws'}


class _Invalid(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise _Invalid(code)


def _head(request, expected_commit):
    _require(type(expected_commit) is str and re.fullmatch('[a-f0-9]{40}',expected_commit) is not None,
        'EXPECTED_COMMIT_INVALID')
    _require(request.get('commit') == expected_commit,'COMMIT_MISMATCH')
    repo=runtime._repo(request['repo'],clean=False)
    runtime._validate_commit(repo,expected_commit)
    _require(runtime._head(repo)==expected_commit,'HEAD_MISMATCH')
    return repo


def _code_receipt(request, repo, expected_commit, scope, evidence, context):
    _require(type(context) is dict and {'bundle','min_sequence'} <= set(context) <= _CONTEXT_FIELDS,
        'CODE_CONTEXT_INVALID')
    _require(type(context['min_sequence']) is int and context['min_sequence']>0,'CODE_CONTEXT_INVALID')
    _require(type(context.get('with_iron_laws',False)) is bool,'CODE_CONTEXT_INVALID')
    # Canonical detachment prevents a caller mutating signed authority during use.
    import json
    context=json.loads(security.canonical(context))
    options=dict(context,trust=request['trust'],tenant_id=scope[0],project_id=scope[1],now=request['now'],local_demo=True)
    result=gate.evaluate(repo,evidence,expected_commit,**options)
    _require(result.get('kind')=='reference_ci_gate' and result.get('outcome') in runtime.EXIT_CODES and
        result.get('exit_code')==runtime.EXIT_CODES[result['outcome']], 'CODE_GATE_INVALID')
    # Only signed-policy success with all commit/profile/evidence checks is bindable.
    if result['outcome']=='error':
        return 'error',None
    _require(result.get('policy_receipt') is not None and result.get('checked_commit')==expected_commit and
        type(result.get('checks')) is dict and all(result['checks'].get(k) is True for k in
        ('expected_commit','head','profile','evidence')), 'CODE_GATE_INVALID')
    verify_options=dict(local_demo=True,tenant_id=scope[0],project_id=scope[1])
    if result.get('input_mode')=='commit_snapshot':verify_options['commit']=expected_commit
    else:_require(result.get('input_mode')=='strict_head','CODE_GATE_INVALID')
    verified=runtime.verify(repo,evidence,**verify_options)
    _require(verified.get('commit_sha')==expected_commit and verified.get('outcome')==result.get('raw_outcome') and
        verified.get('exit_code')==result.get('raw_exit_code'),'CODE_GATE_INCONSISTENT')
    final=gate.evaluate(repo,evidence,expected_commit,**options)
    _require(all(final.get(key)==result.get(key) for key in
        ('kind','outcome','exit_code','raw_outcome','raw_exit_code','checks','checked_commit','input_mode','policy_receipt')),
        'CODE_EVIDENCE_CHANGED')
    again=runtime.verify(repo,evidence,**verify_options)
    _require(again['manifest_digest']==verified['manifest_digest'],'CODE_EVIDENCE_CHANGED')
    binding=dict(manifest_digest=verified['manifest_digest'],
        trusted_context_digest=c.digest(dict(context,trust=request['trust'],tenant_id=scope[0],project_id=scope[1])),
        outcome=result['outcome'],raw_outcome=result['raw_outcome'],checks=result['checks'],
        with_iron_laws=context.get('with_iron_laws',False),commit_sha=expected_commit,input_mode=result['input_mode'])
    return ('ready_for_evidence' if result['outcome']=='allow' else result['outcome']),c.digest(binding)


def prepare(request, expected_commit, *, code_evidence=None, code_context=None,
            expected_subject_digest=None, expected_evaluation_digest=None):
    """Reassess original authorities and AND document and signed code decisions."""
    candidate=dict(kind='project_stage_candidate',schema_version='1',context=security.CONTEXT,
        tenant_id=None,project_id=None,operational_approval=False,stage=None,commit_sha=None,
        subject_digest=None,evaluation_digest=None,assessment=None,code_required=None,code_receipt_digest=None,
        outcome='error',reason_codes=[])
    repo=None
    reasons=set()
    def merge(outcome,reason=None):
        if _RANK[outcome]>_RANK[candidate['outcome']]:candidate['outcome']=outcome
        if reason:reasons.add(reason)
    try:
        _require(type(request) is dict,'ORIGINAL_INPUTS_REQUIRED')
        repo=_head(request,expected_commit)
        candidate['commit_sha']=expected_commit
        report=assessment.assess(**request)
        candidate.update(assessment=report,stage=report['stage'],tenant_id=report['tenant_id'],project_id=report['project_id'],
            subject_digest=report['subject_digest'],evaluation_digest=report['evaluation_digest'])
        scope=(report['tenant_id'],report['project_id'])
        if expected_subject_digest is not None:
            _require(expected_subject_digest==report['subject_digest'],'SUBJECT_DIGEST_MISMATCH')
        if expected_evaluation_digest is not None:
            _require(expected_evaluation_digest==report['evaluation_digest'],'EVALUATION_DIGEST_MISMATCH')
        verified=packs.verify_lock(request['lock'],request['trust'],*scope,request['now'],
            profile_registry=request['profile_registry'],revocations=request['revocations'],
            expected_revocation_digest=request['expected_revocation_digest'],
            min_sequence=request.get('min_sequence',1),min_revocation_epoch=request.get('min_revocation_epoch',1),
            min_profile_revision=request.get('min_profile_revision',1))
        _require(verified['profile_digest']==report['profile_digest'] and verified['lock_digest']==report['lock_digest'] and
            verified['profile']['stage']==report['stage'],'PROFILE_CHANGED')
        candidate['outcome']={'ready_for_stage':'ready_for_evidence','deny':'deny','review_required':'review_required','error':'error'}[report['outcome']]
        if report['outcome']!='ready_for_stage':reasons.add('DOCUMENT_'+report['outcome'].upper())
        if report['counts']['current']==0:merge('review_required','NO_CURRENT_REQUIREMENTS')
        fact=verified['profile']['facts'].get('code_checks_required')
        if fact is None or fact.get('state')!='known':
            merge('review_required','CODE_REQUIREMENT_UNCONFIRMED')
        else:
            _require(fact.get('value_type')=='boolean' and type(fact.get('value')) is bool,'CODE_REQUIREMENT_INVALID')
            candidate['code_required']=fact['value']
            if not fact['value']:
                names=snapshot.run_git(repo,'ls-tree','-rz','--name-only','--full-tree',expected_commit).decode('utf-8').split('\0')
                if any(PurePosixPath(name).suffix.lower() in _CODE_SUFFIXES for name in names if name):
                    merge('review_required','CODE_PRESENT_REQUIRES_REVIEW')
                if code_context is not None or code_evidence is not None:
                    merge('review_required','UNEXPECTED_CODE_CONTEXT')
            elif code_evidence is None or code_context is None:
                merge('review_required','CODE_EVIDENCE_REQUIRED')
            else:
                outcome,digest=_code_receipt(request,repo,expected_commit,scope,code_evidence,code_context)
                candidate['code_receipt_digest']=digest
                merge(outcome,'CODE_'+outcome.upper() if outcome!='ready_for_evidence' else None)
    except _Invalid as error:
        candidate['outcome']='error';reasons.add(str(error))
    except assessment.AssessmentError:
        candidate['outcome']='error';reasons.add('ASSESSMENT_VERIFICATION_FAILED')
    except Exception:
        candidate['outcome']='error';reasons.add('STAGE_VERIFICATION_FAILED')
    finally:
        if repo is not None:
            try:
                _require(runtime._head(repo)==expected_commit,'HEAD_MISMATCH')
            except Exception:
                candidate['outcome']='error';reasons.add('HEAD_MISMATCH')
    candidate['reason_codes']=sorted(reasons)
    candidate['candidate_digest']=c.digest(candidate)
    return candidate


def evaluate(request, expected_commit, *, evidence_store=None, evidence_id=None,
             code_evidence=None, code_context=None, expected_subject_digest=None, expected_evaluation_digest=None):
    """Only a real R7-H store's verified current object can open this stage."""
    candidate=prepare(request,expected_commit,code_evidence=code_evidence,code_context=code_context,
        expected_subject_digest=expected_subject_digest,expected_evaluation_digest=expected_evaluation_digest)
    outcome=candidate['outcome'];reasons=set(candidate['reason_codes']);evidence_ref=None
    try:
        from .evidence import ProjectEvidenceStore
    except ImportError:
        ProjectEvidenceStore=None
    has_store=(ProjectEvidenceStore is not None and type(evidence_store) is ProjectEvidenceStore and
        type(evidence_id) is str and bool(evidence_id))
    if not has_store:
        reasons.add('EVIDENCE_REQUIRED')
        if outcome!='error':outcome='review_required'
    elif outcome=='ready_for_evidence':
        outcome='review_required';reasons.add('EVIDENCE_REQUIRED')
        try:
            # Invoke the trusted implementation, never an instance callback.
            metadata=ProjectEvidenceStore.verify_receipt(evidence_store,evidence_id,candidate)
            _require(type(metadata) is dict,'EVIDENCE_INVALID')
            for key in ('candidate_digest','subject_digest','evaluation_digest','commit_sha','stage','tenant_id','project_id'):
                _require(metadata.get(key)==candidate[key],'EVIDENCE_CANDIDATE_MISMATCH')
            _require(metadata.get('operational_approval') is False and
                metadata.get('evidence_id',metadata.get('item_id'))==evidence_id,'EVIDENCE_INVALID')
            evidence_ref=dict(evidence_id=evidence_id,candidate_digest=candidate['candidate_digest'])
            outcome='allow';reasons.discard('EVIDENCE_REQUIRED')
        except Exception:
            outcome='error';reasons.discard('EVIDENCE_REQUIRED');reasons.add('EVIDENCE_VERIFICATION_FAILED')
    try:
        if candidate['commit_sha'] is not None:_head(request,expected_commit)
    except Exception:
        outcome='error';reasons.add('HEAD_MISMATCH')
    return dict(kind='project_stage_receipt',schema_version='1',context=security.CONTEXT,
        tenant_id=candidate['tenant_id'],project_id=candidate['project_id'],stage=candidate['stage'],
        operational_approval=False,commit_sha=candidate['commit_sha'],subject_digest=candidate['subject_digest'],
        evaluation_digest=candidate['evaluation_digest'],candidate_digest=candidate['candidate_digest'],
        code_receipt_digest=candidate['code_receipt_digest'],evidence_ref=evidence_ref,
        outcome=outcome,exit_code=runtime.EXIT_CODES[outcome],reason_codes=sorted(reasons))
