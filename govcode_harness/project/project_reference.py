"""Eight-requirement local synthetic acceptance, using real signed authorities.

No legal applicability or business test result is inferred here. Attestations only
cover executed structural reference checks and the existing privacy code gate.
"""
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import uuid

from .. import runtime, security, gate, control_plane, evidence_store
from ..reference_cli import ReferenceAuthority, utcnow
from . import assessment, applicability, artifact_snapshot, contracts as c
from . import delivery_trace, document_proposal, packs, profile, reference, stage_gate
from .evidence import ProjectEvidenceStore, StoreError


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def demo(output):
    """Create a fresh private reference folder and return a source-free result."""
    root=runtime._new_directory(output)
    private=root/'private';private.mkdir(mode=0o700)
    a=ReferenceAuthority(private,'TENANT-REFERENCE','PROJECT-R7-REFERENCE')
    scope=dict(tenant_id=a.tenant_id,project_id=a.project_id)
    common=dict(schema_version='1',context=security.CONTEXT,operational_approval=False,**scope)
    now=utcnow();clock=c.timestamp(now)
    end=(clock+dt.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    feed_end=(clock+dt.timedelta(seconds=packs.MAX_FEED_SECONDS)).strftime('%Y-%m-%dT%H:%M:%SZ')
    def write(name,value):
        runtime._write(root/name,value)
        return str(root/name)
    def sign(kind,actor='author',**fields):
        return security.sign(dict(common,actor_id=actor,kind=kind,event_id=uuid.uuid4().hex,created_at=now,**fields),a.keys[actor]['private_path'],actor)
    def blocked(fn):
        try:fn()
        except (ValueError,security.SecurityError,StoreError,control_plane.ControlError):return True
        return False
    checks={}
    bundle=a.policy_bundle(root/'code-policy-registry',now,end)
    code_context=dict(bundle=bundle,min_sequence=1)
    write('code-context.json',code_context)
    write('public-trust.json',a.trust)
    facts=dict(needs_delivery=True,public_web=False,code_checks_required=True)
    source=dict(common,kind='synthetic_source_facts',facts=facts,legal_records='pending')
    write('source-example.json',source)
    p=dict(common,kind='project_profile',id='PROFILE-R7',revision=1,parent_digest=None,jurisdiction='KR',
        project_type='software_delivery',stage='acceptance',owner_ref='author',lifecycle='draft',
        source_refs=[dict(id='SRC-EXAMPLE',version='1',category='example',verification='confirmed',digest=c.digest(source))],
        facts={k:dict(state='known',value_type='boolean',value=v,source_ref='SRC-EXAMPLE') for k,v in facts.items()})
    p['facts']['unknown_condition']=dict(state='unknown',owner_ref='author',reason_ref='CONFIRM-SYNTHETIC-FACT')
    profiles=profile.ProjectProfileRegistry.create(root/'profile-registry',trust=a.trust,**scope)
    def approve_profile(candidate):
        profiles.apply(sign('profile_action',action='revise',profile=candidate,expected_revision=candidate['revision']-1),now)
        target=dict(profile_id=candidate['id'],revision=candidate['revision'],profile_digest=c.digest(candidate),expected_revision=candidate['revision'])
        profiles.apply(sign('profile_action',action='submit',**target),now)
        profiles.apply(sign('profile_approval','approver',decision='approve',reason_ref='SYNTHETIC-PROFILE-REVIEW',not_before=now,expires_at=end,**target),now)
    approve_profile(p)
    def requirement(identity,fact,stages,check):
        return dict(common,kind='requirement_spec',id=identity,version='1',source_ref=p['source_refs'][0],source_category='example',
            source_verification='confirmed',normativity='example',basis_kind='example_policy',
            applicability_expr=dict(op='eq',fact=fact,value=dict(value_type='boolean',value=True)),stages=stages,
            required_artifacts=['ART-DESIGN'],check_refs=[check],review_required=True)
    reqs=[requirement('CURRENT'+str(i),'needs_delivery',['acceptance'],'CHECK-LOG' if i==5 else 'CHECK-TRACE') for i in range(1,6)]
    reqs += [requirement('FUTURE1','needs_delivery',['operations'],'CHECK-TRACE'),
        requirement('EXCLUDED7','public_web',['acceptance'],'CHECK-TRACE'),
        requirement('UNKNOWN8','unknown_condition',['acceptance'],'CHECK-TRACE')]
    registry=packs.RulePackRegistry.create(root/'pack-registry',trust=a.trust,**scope)
    registry.issue_revocations(a.keys['operator']['private_path'],'operator',now=now,expires_at=feed_end,expected_sequence=registry.checkpoint()['sequence'])
    releases=[]
    for identity,domain,selected,adapter,check in [('PACK-DELIVERY','delivery_trace',[r for r in reqs if r['id']!='CURRENT5'],'delivery.trace_integrity','CHECK-TRACE'),
        ('PACK-PRIVACY','privacy_logging',[reqs[4]],'privacy.logging','CHECK-LOG')]:
        manifest=dict(common,kind='rule_pack_manifest',pack_id=identity,version='1',domain=domain,source_refs=p['source_refs'],
            requirement_refs=[reference.reference(r) for r in selected],task_templates=[],check_specs=[dict(id=check,adapter_id=adapter)],
            dependencies=[],not_before=now,expires_at=end)
        for action,actor in [('draft','author'),('submit','author'),('approve','approver')]:
            fields=dict(action=action,pack_id=identity,version='1',pack_digest=packs.pack_digest(manifest,selected),expected_sequence=registry.checkpoint()['sequence'])
            if action=='draft':fields.update(manifest=manifest,requirements=selected)
            if action=='approve':fields.update(reason_ref='SYNTHETIC-PACK-REVIEW',not_before=now,expires_at=end)
            registry.apply(sign('rule_pack_action',actor,**fields),now)
        releases.append(registry.publish(identity,'1',a.keys['operator']['private_path'],'operator',now=now,not_before=now,expires_at=end,
            expected_sequence=registry.checkpoint()['sequence']))
    feed=registry.issue_revocations(a.keys['operator']['private_path'],'operator',now=now,expires_at=feed_end,expected_sequence=registry.checkpoint()['sequence'])
    write('revocations.json',feed)
    def lock(candidate,sequence):
        event=uuid.uuid4().hex
        body=dict(common,kind='project_pack_lock',id='LOCK-R7',version=str(sequence),profile_ref=reference.reference(candidate),
            profile_digest=c.digest(candidate),pack_refs=[r['payload']['pack_ref'] for r in releases],policy_bundle_refs=[],
            selection_review_ref=event,sequence=sequence,not_before=now,expires_at=end)
        request=sign('pack_selection_request',lock=body)
        approval=sign('pack_selection_review','approver',request_digest=c.digest(request),decision='approve',reason_ref='SYNTHETIC-SELECTION',
            not_before=now,expires_at=end)
        approval['payload']['event_id']=event
        approval=security.sign(approval['payload'],a.keys['approver']['private_path'],'approver')
        return registry.publish_lock(request,approval,releases,profiles,a.keys['operator']['private_path'],'operator',now=now,
            expected_sequence=registry.checkpoint()['sequence'])
    first_lock=lock(p,1)
    def exclusions(current_lock,candidate,names):
        return [sign('applicability_review','approver',lock_digest=c.digest(current_lock),profile_digest=c.digest(candidate),requirement_ref=reference.reference(r),
            subject_digest=applicability.review_subject(c.digest(current_lock),c.digest(candidate),reference.reference(r),**scope),
            decision='not_applicable',reason_ref='SYNTHETIC-CONDITION-FALSE',not_before=now,expires_at=end) for r in reqs if r['id'] in names]
    first_exclusions=exclusions(first_lock,p,{'EXCLUDED7'})
    repo=root/'repository-before';repo.mkdir(mode=0o700)
    runtime._git(repo,'init','-b','main')
    (repo/'app.py').write_text(runtime.AFTER_SOURCE)
    artifacts=[]
    for identity,kind in [('ART-DESIGN','design'),('ART-PLAN','test_plan'),('ART-RESULT','test_result'),('ART-REVIEW','review_record')]:
        content='# '+identity+'\n\nSynthetic reference only. Structural chain checks are executed by the reference. Business acceptance and legal records remain pending.\n'
        (repo/(identity+'.md')).write_text(content)
        artifacts.append(dict(common,kind='artifact_ref',id=identity,version='1',artifact_kind=kind,relative_path=identity+'.md',content_digest=hashlib.sha256(content.encode()).hexdigest()))
    index=dict(common,kind='project_artifact_index',requirements=reqs,artifacts=artifacts,traces=[])
    def link(left,right,relation):
        index['traces'].append(dict(common,kind='trace_link',id='LINK-'+str(len(index['traces'])+1),version='1',
            from_ref=reference.reference(left),to_ref=reference.reference(right),relation=relation))
    for r in reqs:
        if r['id']!='CURRENT3':link(r,artifacts[0],'implements')
    for left,right,relation in zip(artifacts,artifacts[1:],('verifies','reports','reviews')):link(left,right,relation)
    (repo/'index.json').write_bytes(security.canonical(index))
    runtime._git(repo,'add','--all');runtime._git(repo,'commit','-m','Synthetic eight-requirement reference baseline')
    first_commit=runtime._head(repo)
    code_options=dict(local_demo=True,**scope)
    runtime.scan(repo,root/'code-before',commit=first_commit,**code_options)
    code_before=gate.evaluate(repo,root/'code-before',first_commit,trust=a.trust,**code_context,now=now,**code_options)
    _require(code_before['outcome']=='allow','CODE_REFERENCE_FAILED')
    tools={name:dict(adapter_id=adapter,tool_digest=runtime._tool_digest()) for name,adapter in [('CHECK-TRACE','delivery.trace_integrity'),('CHECK-LOG','privacy.logging')]}
    def proofs(current_repo,commit,names,code_result):
        captured=artifact_snapshot.collect(current_repo,commit,'index.json',**scope)
        inspected=delivery_trace.inspect(captured,now=now,expected_requirements=reqs)
        result=[]
        for r in reqs:
            if r['id'] not in names:continue
            # Attest only an actual structural check; privacy also requires the real signed code gate.
            _require(not any(f.get('entity_id')==r['id'] and f['check_id']=='trace_integrity' for f in inspected['findings']),'TRACE_CHECK_FAILED')
            _require(all(ch['status']=='pass' for ch in inspected['checks'] if ch['check_id']=='artifact_structure'),'STRUCTURE_CHECK_FAILED')
            if r['id']=='CURRENT5':_require(code_result['outcome']=='allow','PRIVACY_CHECK_FAILED')
            check=r['check_refs'][0]
            result.append(sign('artifact_test_attestation','operator',not_before=now,expires_at=end,commit_sha=commit,
                artifact_manifest_digest=c.digest(captured['manifest']),requirement_ref=reference.reference(r),result_artifact_ref=reference.reference(artifacts[2]),
                check_id=check,result='pass',**tools[check]))
        return result
    def request(current_repo,commit,current_lock,app_reviews,result_receipts,reviews=()):
        return dict(repo=str(current_repo),commit=commit,index_path='index.json',profile_registry=profiles,lock=current_lock,trust=a.trust,now=now,
            revocations=feed,expected_revocation_digest=c.digest(feed),applicability_reviews=app_reviews,result_receipts=result_receipts,
            result_tools=tools,reviews=list(reviews),min_sequence=current_lock['payload']['lock']['sequence'] if 'lock' in current_lock['payload'] else 1)
    def review(report,name,actor='approver'):
        row=next(r for r in report['requirements'] if r['requirement_ref']['id']==name)
        return sign('project_artifact_review',actor,not_before=now,expires_at=end,subject_digest=report['subject_digest'],
            requirement_ref=row['requirement_ref'],artifact_digests=row['artifact_digests'],decision='approved',reason_ref='SYNTHETIC-STRUCTURE-REVIEW')
    initial_proofs=proofs(repo,first_commit,{'CURRENT1','CURRENT2','CURRENT4'},code_before)
    before_request=request(repo,first_commit,first_lock,first_exclusions,initial_proofs)
    preview=assessment.assess(**before_request)
    old_reviews=[review(preview,n) for n in ('CURRENT1','CURRENT2')]
    before_request['reviews']=old_reviews
    before=assessment.assess(**before_request)
    write('assessment-before.json',before);write('work-plan-before.json',before['work_items'])
    checks['initial_denominator']=tuple(before['counts'][k] for k in ('total','applicable','not_applicable','pending','current','not_due'))==(8,6,1,1,5,1)
    checks['distinct_initial_blockers']=tuple(before['counts'][k] for k in ('satisfied','unsatisfied','review_required','not_evaluated'))==(2,1,2,1)
    initial_stage=stage_gate.prepare(before_request,first_commit,code_evidence=root/'code-before',code_context=code_context)
    checks['pending_blocks']=initial_stage['outcome']!='ready_for_evidence'
    write('stage-before.json',initial_stage)
    signer=dict(private_path=a.keys['operator']['private_path'],key_id='operator')
    store=ProjectEvidenceStore.create(root/'store',a.trust,**scope,**signer)
    before_id=store.put(before_request,first_commit,retain_until=end,code_evidence=root/'code-before',code_context=code_context)
    # The sole source repair adds the missing requirement-to-design edge.
    link(reqs[2],artifacts[0],'implements')
    proposal=document_proposal.propose(repo,first_commit,'index.json',{'index.json':security.canonical(index).decode()},a.trust,now,
        **scope,private_path=a.keys['author']['private_path'],key_id='author',expires_at=end)
    approval=document_proposal.approve(proposal,a.trust,now,private_path=a.keys['approver']['private_path'],key_id='approver',expires_at=end)
    write('private/proposal.json',proposal);write('private/proposal-approval.json',approval)
    applied=document_proposal.apply(repo,proposal,approval,a.trust,now,output=root/'repository-after')
    write('document-application.json',applied)
    final_repo=root/'repository-after';commit=applied['new_commit']
    checks['isolated_trace_only_repair']=applied['changed_paths']==['index.json'] and runtime._head(repo)==first_commit and runtime._git(final_repo,'rev-parse','HEAD^').decode().strip()==first_commit
    p2=copy.deepcopy(p);p2.update(revision=2,parent_digest=c.digest(p))
    p2['facts']['unknown_condition']=dict(state='known',value_type='boolean',value=False,source_ref='SRC-EXAMPLE')
    # Record a new, explicitly synthetic source revision for the confirmed fact.
    source2=dict(source,facts=dict(facts,unknown_condition=False));write('source-example-v2.json',source2)
    p2['source_refs']=[dict(p['source_refs'][0],version='2',digest=c.digest(source2))]
    approve_profile(p2);final_lock=lock(p2,2)
    final_exclusions=exclusions(final_lock,p2,{'EXCLUDED7','UNKNOWN8'})
    runtime.scan(final_repo,root/'code-after',commit=commit,**code_options)
    code_after=gate.evaluate(final_repo,root/'code-after',commit,trust=a.trust,**code_context,now=now,**code_options)
    final_proofs=proofs(final_repo,commit,{'CURRENT'+str(i) for i in range(1,6)},code_after)
    final_request=request(final_repo,commit,final_lock,final_exclusions,final_proofs)
    final_preview=assessment.assess(**final_request)
    final_reviews=[review(final_preview,'CURRENT'+str(i)) for i in range(1,5)]
    final_request['reviews']=final_reviews
    checks['old_review_rejected']=blocked(lambda:assessment.assess(**dict(final_request,reviews=old_reviews)))
    stale=assessment.assess(**dict(final_request,result_receipts=initial_proofs,reviews=[]))
    checks['old_result_rejected']=stale['outcome']=='error'
    checks['old_lock_rejected']=blocked(lambda:assessment.assess(**dict(final_request,lock=first_lock,applicability_reviews=first_exclusions)))
    checks['old_commit_rejected']=stage_gate.prepare(final_request,first_commit)['outcome']=='error'
    checks['unsigned_pass_not_trusted']=assessment.assess(**dict(final_request,result_receipts=[dict(payload={'result':'pass'})],reviews=[]))['outcome']=='error'
    checks['author_review_denied']=blocked(lambda:assessment.assess(**dict(final_request,reviews=[review(final_preview,'CURRENT1','author')])))
    checks['code_evidence_required']=stage_gate.prepare(final_request,commit)['outcome']!='ready_for_evidence'
    # Persist caller-protected original inputs for a real ProjectService POST.
    write('profile-v1.json',p);write('profile-v2.json',p2);write('lock-v1.json',first_lock);write('pack-lock.json',final_lock)
    write('profile-checkpoint.json',profiles.checkpoint());write('pack-checkpoint.json',registry.checkpoint())
    write('revocation-anchor.json',dict(epoch=feed['payload']['epoch'],digest=c.digest(feed)))
    args=dict(repo=str(final_repo),commit=commit,index='index.json',**scope,profile_registry=str(root/'profile-registry'),
        profile_checkpoint=str(root/'profile-checkpoint.json'),lock=str(root/'pack-lock.json'),trust=str(root/'public-trust.json'),
        revocations=str(root/'revocations.json'),expected_revocation_digest=c.digest(feed),result_tools=write('result-tools.json',tools),
        applicability_review=[write('applicability-review-'+str(i)+'.json',v) for i,v in enumerate(final_exclusions)],
        result_receipt=[write('result-proof-'+str(i)+'.json',v) for i,v in enumerate(final_proofs)],
        artifact_review=[write('artifact-review-'+str(i)+'.json',v) for i,v in enumerate(final_reviews)],
        min_sequence=2,min_profile_revision=2,min_revocation_epoch=1)
    evidence_store.EvidenceStore.create(root/'legacy-store',a.trust,**scope,**signer)
    token_dir=root/'tokens';token_dir.mkdir(mode=0o700)
    principals=[];tokens={}
    for actor,key in a.keys.items():
        token=secrets.token_urlsafe(32);tokens[actor]=token
        path=token_dir/(actor+'.token');path.write_text(token);path.chmod(0o600)
        principals.append(dict(token_sha256=hashlib.sha256(token.encode()).hexdigest(),actor_id=actor,roles=a.trust['keys'][actor]['roles'],
            **scope,key_id=actor,private_path=key['private_path']))
    context=dict(**scope,assessment=args,control_root=str(root/'project-control'))
    config=dict(context=security.CONTEXT,operational_approval=False,trust=a.trust,principals=principals,project_contexts=[context],
        scopes=[dict(**scope,registry_root=str(root/'code-policy-registry'),store_root=str(root/'legacy-store'),control_root=str(root/'legacy-control'),
            operator_signer=signer,runs=[],finding_ids=[])])
    desk=control_plane.Desk(config)
    service=desk.project_service
    approver=desk.authenticate(tokens['approver']);author=desk.authenticate(tokens['author'])
    post=dict(requirement_id='CURRENT5',decision='approved',reason_ref='SYNTHETIC-API-REVIEW',expected_subject_digest=final_preview['subject_digest'])
    checks['api_author_review_denied']=blocked(lambda:service.handle('POST','/api/projects/reviews',author,post,now))
    api_review=service.handle('POST','/api/projects/reviews',approver,post,now)
    final_request,after=service.assess(context,now,approver)
    checks['api_independent_review']=api_review['state']=='approved' and after['counts']['satisfied']==5
    write('assessment-after.json',after);write('work-plan-after.json',after['work_items'])
    # Separate adversarial repository: actual risky logging yields a signed failure,
    # never a fictional passing privacy result. It cannot open the combined gate.
    negative_repo=root/'repository-unsafe';shutil.copytree(final_repo,negative_repo)
    (negative_repo/'app.py').write_text(runtime.BEFORE_SOURCE)
    runtime._git(negative_repo,'add','--','app.py')
    runtime._git(negative_repo,'commit','-m','Synthetic negative: raw logging must block')
    negative_commit=runtime._head(negative_repo)
    runtime.scan(negative_repo,root/'code-unsafe',commit=negative_commit,**code_options)
    negative_code=gate.evaluate(negative_repo,root/'code-unsafe',negative_commit,trust=a.trust,**code_context,now=now,**code_options)
    negative_capture=artifact_snapshot.collect(negative_repo,negative_commit,'index.json',**scope)
    negative_proofs=[]
    for proof in final_proofs:
        payload=dict(proof['payload'],event_id=uuid.uuid4().hex,commit_sha=negative_commit,
            artifact_manifest_digest=c.digest(negative_capture['manifest']))
        if payload['check_id']=='CHECK-LOG':payload['result']='fail'
        negative_proofs.append(security.sign(payload,a.keys['operator']['private_path'],'operator'))
    negative_request=dict(final_request,repo=str(negative_repo),commit=negative_commit,result_receipts=negative_proofs,reviews=[])
    negative_preview=assessment.assess(**negative_request)
    negative_request['reviews']=[review(negative_preview,'CURRENT'+str(i)) for i in range(1,6)]
    negative_stage=stage_gate.prepare(negative_request,negative_commit,code_evidence=root/'code-unsafe',code_context=code_context)
    checks['unsafe_code_blocks']=negative_code['outcome']=='deny' and negative_stage['outcome']=='deny'
    write('stage-unsafe-negative.json',negative_stage)
    checks['report_flags_rejected']=stage_gate.prepare(dict(after,code_passed=True,verified=True),commit)['outcome']=='error'
    checks['code_context_flags_rejected']=stage_gate.prepare(final_request,commit,code_evidence=root/'code-after',
        code_context=dict(code_context,verified=True,code_passed=True))['outcome']=='error'
    code_kwargs=dict(code_evidence=root/'code-after',code_context=code_context)
    candidate=stage_gate.prepare(final_request,commit,**code_kwargs)
    checks['current_stage_ready']=candidate['outcome']=='ready_for_evidence'
    checks['stored_receipt_required']=stage_gate.evaluate(final_request,commit,**code_kwargs)['outcome']=='review_required'
    final_id=store.put(final_request,commit,retain_until=end,parent_id=before_id,**code_kwargs)
    def auth(action,item,params=None,actor='operator'):
        return security.sign(dict(common,actor_id=actor,kind='project_store_authorization',store_id=store.store_id,action=action,evidence_id=item,
            event_id=uuid.uuid4().hex,time=utcnow(),parameters_digest=c.digest(params or {})),a.keys[actor]['private_path'],actor)
    historical=store.read(before_id,auth('read',before_id,actor='auditor'))
    checks['historical_not_release']=historical['integrity_verified'] and historical['release_approval'] is False
    replay=auth('read',final_id,actor='auditor');store.read(final_id,replay)
    checks['nonce_replay_denied']=blocked(lambda:store.read(final_id,replay))
    checks['operator_read_denied']=blocked(lambda:store.read(final_id,auth('read',final_id)))
    checks['retention_blocks_delete']=blocked(lambda:store.delete(final_id,auth('delete',final_id)))
    store.set_hold(final_id,True,auth('set_hold',final_id,{'enabled':True}))
    checks['hold_blocks_delete']=blocked(lambda:store.delete(final_id,auth('delete',final_id)))
    # Tamper only a separate copy, retaining the original protected authority.
    shutil.copytree(store.root,root/'tamper-store')
    (root/'tamper-store'/'objects'/final_id/'projection.json').write_text('{}')
    checks['projection_tamper_rejected']=blocked(lambda:ProjectEvidenceStore(root/'tamper-store',a.trust,checkpoint=store.checkpoint()))
    backup=root/'backup';cp=store.backup(backup,auth('backup','STORE',{'destination':str(backup)}))
    write('protected-backup-checkpoint.json',cp)
    restored_path=root/'restored-store'
    rejected_path=root/'rejected-restore'
    checks['protected_checkpoint_required']=blocked(lambda:ProjectEvidenceStore.restore(backup,rejected_path,a.trust,a.tenant_id,a.project_id,
        auth('restore','STORE',{'destination':str(rejected_path)}),expected_head_digest='f'*64,minimum_sequence=cp['sequence'],**signer)) and not rejected_path.exists()
    restored=ProjectEvidenceStore.restore(backup,restored_path,a.trust,a.tenant_id,a.project_id,
        auth('restore','STORE',{'destination':str(restored_path)}),expected_head_digest=cp['head_digest'],minimum_sequence=cp['sequence'],**signer)
    historical_restored=restored.read(final_id,auth('read',final_id,actor='auditor'))
    checks['backup_restore_verified']=historical_restored['integrity_verified'] and not historical_restored['release_approval']
    shutil.rmtree(store.root)
    final_stage=stage_gate.evaluate(final_request,commit,evidence_store=restored,evidence_id=final_id,**code_kwargs)
    checks['restored_current_gate_allow']=final_stage['outcome']=='allow'
    checks['old_evidence_unusable']=stage_gate.evaluate(final_request,commit,evidence_store=restored,evidence_id=before_id,**code_kwargs)['outcome']=='error'
    write('stage-after.json',final_stage)
    evidence_config=write('project-evidence-config.json',dict(root=str(restored_path),checkpoint=restored.checkpoint()))
    context['stage_bindings']=dict(expected_commit=commit,expected_subject_digest=after['subject_digest'],expected_evaluation_digest=after['evaluation_digest'],
        evidence_store=evidence_config,evidence_id=final_id,code_context=str(root/'code-context.json'),code_evidence=str(root/'code-after'))
    config['project_contexts']=[context]
    write('control-config.json',config)
    final_desk=control_plane.Desk(config)
    for actor in ('author','operator','auditor'):
        value=final_desk.project_service.handle('GET','/api/projects/current',final_desk.authenticate(tokens[actor]),{},now)
        checks['api_'+actor+'_current']=value['counts']['satisfied']==5 and value['stage_gate']['allowed'] is True
    checks['source_free_evidence']=all(secret not in json.dumps(historical_restored) for secret in ('new_content','private_path','public_key','relative_path','facts'))
    checks['final_denominator']=tuple(after['counts'][k] for k in ('total','applicable','not_applicable','pending','satisfied','not_due'))==(8,6,2,0,5,1)
    checks['all_current_code_checks']=code_after['outcome']=='allow' and code_before['outcome']=='allow'
    _require(all(v is True for v in checks.values()),'REFERENCE_CHECK_FAILED:'+','.join(k for k,v in checks.items() if v is not True))
    result=dict(kind='project_reference_demo',context=security.CONTEXT,operational_approval=False,real_model_executed=False,legal_records='pending',whole_project_complete=False,
        total_requirements=8,current_stage_satisfied=5,not_due=1,approved_exclusions=2,
        before=dict(counts=before['counts'],assessment_outcome=before['outcome'],stage_outcome=initial_stage['outcome'],assessment='assessment-before.json'),
        after=dict(counts=after['counts'],assessment_outcome=after['outcome'],stage_outcome=final_stage['outcome'],assessment='assessment-after.json'),
        checks=checks,files=dict(control='control-config.json',stage='stage-after.json',backup_checkpoint='protected-backup-checkpoint.json',
            evidence_config='project-evidence-config.json',proposal='private/proposal.json',application='document-application.json'))
    write('project-reference-result.json',result)
    return result
