"""Fresh synthetic-reference integration. Keys never leave the new private folder."""
from datetime import datetime, timedelta, timezone
import uuid
from . import runtime


def utcnow():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class ReferenceAuthority:
    """Distinct synthetic actors, real Ed25519 signatures, caller-owned trust."""
    def __init__(self, root, tenant_id, project_id):
        from . import security
        self.tenant_id, self.project_id = tenant_id, project_id
        self.keys = {}
        self.trust = {'context':'synthetic_reference', 'keys':{}}
        for actor, role in [('author','author'), ('approver','approver'), ('operator','operator'), ('auditor','auditor')]:
            key = security.generate_keypair(root / actor, actor)
            self.keys[actor] = key
            self.trust['keys'][actor] = dict(public_key=key['public_key'], actor_id=actor,
                roles=[role], tenant_id=tenant_id, project_id=project_id, revoked=False)

    def sign(self, actor, payload):
        from . import security
        return security.sign(dict(context='synthetic_reference', tenant_id=self.tenant_id,
            project_id=self.project_id, actor_id=actor, **payload), self.keys[actor]['private_path'], actor)

    def policy_bundle(self, root, now, end):
        from . import governance
        policy = runtime._profile((self.tenant_id,self.project_id))
        registry = governance.PolicyRegistry.create(root, self.tenant_id, self.project_id, self.trust)
        for action, actor in [('draft','author'), ('submit','author'), ('approve','approver')]:
            payload = dict(action=action, event_id='event-'+uuid.uuid4().hex, created_at=now)
            if action == 'draft': payload.update(policy=policy, obligations=[])
            else: payload.update(policy_id=policy['id'], version=policy['version'], policy_digest=governance.digest(policy))
            registry.apply(self.sign(actor,payload), now)
        return registry.issue_bundle([{'id':policy['id'],'version':policy['version']}],
            self.keys['operator']['private_path'], 'operator', now, end, 1)

    def authorization(self, action, item):
        actor = 'auditor' if action == 'read' else 'operator'
        return self.sign(actor, dict(kind='store_authorization', action=action,
            archive_id=item, event_id='authorization-'+uuid.uuid4().hex, time=utcnow()))


def _model_reference(root, repo, authority, before, now, end):
    from . import model_gateway, patching
    base = runtime.digest(runtime.BEFORE_SOURCE.encode())
    finding = runtime._read(root/'before'/'finding-0001.json')
    request = dict(context='synthetic_reference',tenant_id=authority.tenant_id,
        project_id=authority.project_id,run_id=before['run_id'],commit_sha=runtime._head(repo),
        findings=[dict(id=finding['id'],path='complaints.py',line=finding['location']['line'],
            category=finding['category'],severity=finding['severity'])],
        files=[dict(path='complaints.py',base_sha256=base)],
        safe_log_fields=['request_id','operation','result_code'])
    response = {**{k:request[k] for k in ('context','tenant_id','project_id','run_id','commit_sha')},
        'format':'govcode-patch-proposal-v1','model':dict(id='fixture',backend='fixture',prompt_version='1'),
        'changes':[dict(path='complaints.py',base_sha256=base,new_content=runtime.AFTER_SOURCE)]}
    proposal = model_gateway.propose(request,model_gateway.FixtureProvider(response))
    approval = authority.sign('approver',dict(kind='patch_approval',
        proposal_digest=model_gateway.proposal_digest(proposal),base_commit=request['commit_sha'],
        run_id=before['run_id'],paths=['complaints.py'],created_at=now,expires_at=end,
        event_id='patch-'+uuid.uuid4().hex))
    receipt = patching.apply_proposal(repo,proposal,approval,authority.trust,root/'model-patch',
        tenant_id=authority.tenant_id,project_id=authority.project_id)
    return dict(backend='fixture',real_model_executed=False,verdict=receipt['verdict'],
        sandbox_verified=receipt['sandbox_verified'],checks=receipt['checks'],
        reason_code=receipt.get('reason_code'))


def _control_reference(root, repo, authority, runs, archive_id):
    import hashlib, http.client, json, threading
    from . import control_plane
    tokens = {actor:uuid.uuid4().hex+uuid.uuid4().hex for actor in authority.keys}
    principals = [dict(token_sha256=hashlib.sha256(tokens[actor].encode()).hexdigest(),
        actor_id=actor,roles=authority.trust['keys'][actor]['roles'],tenant_id=authority.tenant_id,
        project_id=authority.project_id,key_id=actor,private_path=key['private_path'])
        for actor,key in authority.keys.items()]
    registered = []
    if len(runs) != 2:raise runtime.HarnessError('REFERENCE_RUNS_INVALID')
    for name,receipt in zip(('before','after'),runs):
        evidence=root/name
        checked=runtime._verify(repo,evidence,current=False,expected_context=(authority.tenant_id,authority.project_id))
        if checked['run_id'] != receipt['run_id'] or checked['manifest_digest'] != receipt['manifest_digest']:
            raise runtime.HarnessError('REFERENCE_RUNS_INVALID')
        run=runtime._read(evidence/'run.json')
        execution=runtime._read(evidence/'execution.json')
        mode=runtime._read_input_scope(execution,run['commit_sha'])
        analysis=runtime._analysis(repo,run['commit_sha'],with_iron_laws=runtime._detector_profile(execution),input_mode=mode)
        canonical_run,_,findings,_=runtime._objects(repo,run['commit_sha'],analysis,run['id'],run['started_at'],run['parent_run_id'],(authority.tenant_id,authority.project_id))
        registered.append(dict(canonical_run,outcome=checked['outcome'],manifest_digest=checked['manifest_digest'],findings=findings))
    scope = dict(tenant_id=authority.tenant_id,project_id=authority.project_id,
        registry_root=str(root/'registry'),store_root=str(root/'restored'),control_root=str(root/'control'),
        operator_signer=dict(key_id='operator',private_path=authority.keys['operator']['private_path']),
        runs=registered,finding_ids=[f['id'] for run in registered for f in run['findings']])
    from .archive import write as write_private
    write_private(root/'control-bootstrap.json', dict(context='synthetic_reference',tokens=tokens))
    config = dict(context='synthetic_reference',operational_approval=False,
        trust=authority.trust,scopes=[scope],principals=principals)
    runtime._write(root/'control-config.json',config)
    server=control_plane.create_server(config,port=0)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    def call(method,path,actor=None,body=None):
        connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
        headers={'Content-Type':'application/json'}
        if actor:headers['Authorization']='Bearer '+tokens[actor]
        try:
            connection.request(method,path,body=json.dumps(body) if body is not None else None,headers=headers)
            response=connection.getresponse();response.read();return response.status
        finally:connection.close()
    try:
        checks=dict(auditor_runs=call('GET','/api/runs','auditor')==200,
            auditor_evidence=call('GET','/api/evidence/'+archive_id,'auditor')==200,
            author_approval_blocked=call('POST','/api/policies/approve','author',{})==403,
            cross_tenant_blocked=call('GET','/api/runs?tenant_id=other','auditor')==403,
            unauthenticated_blocked=call('GET','/api/runs')==401)
        if not all(checks.values()):raise runtime.HarnessError('REFERENCE_CONTROL_FAILED')
        return checks
    finally:
        server.shutdown();worker.join(timeout=5);server.server_close()


def demo(output):
    from . import gate, archive, evidence_store
    root = runtime._new_directory(output)
    authority = ReferenceAuthority(root, 'TENANT-REFERENCE', 'PROJECT-REFERENCE')
    now = utcnow()
    end = (datetime.strptime(now,'%Y-%m-%dT%H:%M:%SZ')+timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    bundle = authority.policy_bundle(root/'registry', now, end)
    runtime._write(root/'public-trust.json', authority.trust)
    runtime._write(root/'policy-bundle.json', bundle)
    repo = root/'repository'; repo.mkdir(mode=0o700)
    runtime._git(repo,'init','-b','main')
    options = dict(local_demo=True, tenant_id=authority.tenant_id, project_id=authority.project_id)
    gate_options = dict(options, bundle=bundle, trust=authority.trust, min_sequence=1)
    (repo/'complaints.py').write_text(runtime.BEFORE_SOURCE)
    runtime._git(repo,'add','--','complaints.py')
    runtime._git(repo,'commit','-m','Synthetic risky reference fixture')
    before = runtime.scan(repo,root/'before',**options)
    denied = gate.evaluate(repo,root/'before',runtime._head(repo),**gate_options)
    if denied['outcome'] != 'deny': raise runtime.HarnessError('REFERENCE_EXPECTED_DENY')
    model_checks = _model_reference(root,repo,authority,before,now,end)
    if (repo/'complaints.py').read_text() != runtime.BEFORE_SOURCE:
        raise runtime.HarnessError('REPAIR_PRECONDITION_FAILED')
    (repo/'complaints.py').write_text(runtime.AFTER_SOURCE)
    runtime._git(repo,'add','--','complaints.py')
    runtime._git(repo,'commit','-m','Preserve audit and remove synthetic raw logging')
    after = runtime.scan(repo,root/'after',parent=root/'before',**options)
    allowed = gate.evaluate(repo,root/'after',runtime._head(repo),**gate_options)
    if allowed['outcome'] != 'allow': raise runtime.HarnessError('REFERENCE_EXPECTED_ALLOW')
    key = dict(private_path=authority.keys['operator']['private_path'],key_id='operator')
    exported = archive.export_bundle(repo,root/'after',root/'archive',trust=authority.trust,
        tenant_id=authority.tenant_id, project_id=authority.project_id,created_at=now,retain_until=now,**key)
    store = evidence_store.EvidenceStore.create(root/'store',authority.trust,
        authority.tenant_id,authority.project_id,**key)
    item = store.put(root/'archive')
    store.read(item,authority.authorization('read',item))
    store.set_hold(item,True,authority.authorization('set_hold',item))
    try:
        store.delete(item,authority.authorization('delete',item))
    except evidence_store.StoreError as exc:
        if exc.code != 'LEGAL_HOLD': raise
    else: raise runtime.HarnessError('REFERENCE_HOLD_FAILED')
    backup = store.backup(root/'backup',authority.authorization('backup','store'))
    restored = evidence_store.EvidenceStore.restore(root/'backup',root/'restored',authority.trust,
        authority.tenant_id,authority.project_id,authority.authorization('restore','store'),
        expected_head_digest=backup['head_digest'],minimum_sequence=backup['sequence'],**key)
    restored.read(item,authority.authorization('read',item))
    control_checks = _control_reference(root,repo,authority,[before,after],item)
    store.set_hold(item,False,authority.authorization('set_hold',item))
    store.delete(item,authority.authorization('delete',item))
    report = dict(context='synthetic_reference',operational_approval=False,
        before=denied,after=allowed,regression=runtime.regression(),
        archive_id=exported['archive_id'],model_checks=model_checks,control_checks=control_checks,store_checks=dict(read=True,hold_blocks_delete=True,
        backup_restore=True,retention_expired_delete=True),legal_records='pending')
    runtime._write(root/'reference-result.json',report)
    return report


def main(argv=None):
    import argparse, json
    parser = argparse.ArgumentParser(description='Fresh private synthetic reference demonstration')
    parser.add_argument('--output',required=True)
    args = parser.parse_args(argv)
    try:
        report = demo(args.output)
        print(json.dumps(dict(context=report['context'],operational_approval=False,
            before=report['before']['outcome'],after=report['after']['outcome'],
            store_checks=report['store_checks'],control_checks=report['control_checks'],
            model_checks=report['model_checks'],legal_records=report['legal_records']),sort_keys=True))
        def required(checks, names):
            return set(names) <= set(checks) and all(value is True for value in checks.values())
        complete = (report['model_checks']['verdict'] == 'verified' and
            report['model_checks']['sandbox_verified'] is True and
            required(report['model_checks']['checks'], ('static','functional','audit','privacy','isolation')) and
            required(report['control_checks'], ('auditor_runs','auditor_evidence','author_approval_blocked','cross_tenant_blocked','unauthenticated_blocked')) and
            required(report['store_checks'], ('read','hold_blocks_delete','backup_restore','retention_expired_delete')) and
            required(report['regression'], ('response_preserved','audit_preserved','body_removed_from_app_log')) and report['before']['outcome'] == 'deny' and
            report['after']['outcome'] == 'allow')
        return 0 if complete else 3
    except Exception:
        print(json.dumps({'outcome':'error','code':'REFERENCE_DEMO_FAILED','operational_approval':False}))
        return 4
