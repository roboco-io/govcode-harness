"""Runnable R7-C/D synthetic authority; no detector or compliance gate is executed."""
import datetime as dt
import json

from .. import security
from . import contracts as c, profile as profiles, packs, applicability


def reference(value):
    return dict(kind=value['kind'],id=value.get('id',value.get('pack_id')),
                version=str(value.get('revision',value.get('version'))),digest=c.digest(value))


def example_packs(profile, now, expires_at):
    common = {k:profile[k] for k in ('schema_version','context','tenant_id','project_id','operational_approval')}
    source = profile['source_refs'][0]
    def requirement(name, fact, value_type, value, check):
        return dict(common,kind='requirement_spec',id=name,version='0.1.0',source_ref=source,
            source_category='example',source_verification='confirmed',normativity='example',basis_kind='example_policy',
            applicability_expr=dict(op='eq',fact=fact,value=dict(value_type=value_type,value=value)),
            stages=['acceptance'],required_artifacts=['ART-TRACE' if check=='CHECK-TRACE' else 'ART-LOG-RECHECK'],
            check_refs=[check],review_required=True)
    delivery = [requirement('REQ-DEL-WEB','public_web','boolean',True,'CHECK-TRACE'),
                requirement('REQ-DEL-CONTRACT','procurement_type','string','synthetic_fixed_scope','CHECK-TRACE')]
    privacy = [requirement('REQ-PRIVACY-LOG','processes_personal_data','boolean',True,'CHECK-LOG')]
    def manifest(name, domain, requirements, adapter, check, dependencies):
        return dict(common,kind='rule_pack_manifest',pack_id=name,version='0.1.0',domain=domain,
            source_refs=[source],requirement_refs=[reference(r) for r in requirements],task_templates=[],
            check_specs=[dict(id=check,adapter_id=adapter)],dependencies=dependencies,
            not_before=now,expires_at=expires_at)
    d = manifest('PACK-DELIVERY-TRACE','delivery_trace',delivery,'delivery.trace_integrity','CHECK-TRACE',[])
    p = manifest('PACK-PRIVACY-LOG','privacy_logging',privacy,'privacy.logging','CHECK-LOG',[reference(d)])
    return (d,delivery),(p,privacy)


@packs._guard
def demo(output):
    root = security.safe_path(output)
    packs._require(not root.exists(),'OUTPUT_EXISTS')
    root.mkdir(mode=0o700)
    (root/'private').mkdir(mode=0o700)
    clock = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    now = clock.strftime('%Y-%m-%dT%H:%M:%SZ')
    end = (clock+dt.timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
    feed_end = (clock+dt.timedelta(seconds=packs.MAX_FEED_SECONDS)).strftime('%Y-%m-%dT%H:%M:%SZ')
    scope = dict(tenant_id='TENANT-REFERENCE',project_id='PROJECT-DELIVERY-REFERENCE')
    common = dict(schema_version='1',context=security.CONTEXT,operational_approval=False,**scope)
    trust,keys = dict(context=security.CONTEXT,keys={}),{}
    for actor,roles in [('author',['author','approver']),('approver',['approver']),('operator',['operator'])]:
        key = security.generate_keypair(root/'private'/actor,actor)
        keys[actor] = key
        trust['keys'][actor] = dict(actor_id=actor,public_key=key['public_key'],roles=roles,revoked=False,**scope)
    def sign(kind, actor, **fields):
        import uuid
        payload = dict(common,kind=kind,actor_id=actor,event_id=uuid.uuid4().hex,created_at=now)
        payload.update(fields)
        return security.sign(payload,keys[actor]['private_path'],actor)
    write = lambda name,value: profiles._write_new(root/name,value)
    source = dict(context=security.CONTEXT,public_web=False,processes_personal_data=True,procurement_type='synthetic_fixed_scope')
    write('source-example.json',source)
    profile = dict(common,kind='project_profile',id='PROFILE-PACKS',revision=1,parent_digest=None,jurisdiction='KR',
        project_type='software_delivery',stage='acceptance',owner_ref='author',lifecycle='draft',
        source_refs=[dict(id='SRC-EXAMPLE',version='1',category='example',verification='confirmed',digest=c.digest(source))],
        facts={name:dict(state='known',value_type='boolean',value=source[name],source_ref='SRC-EXAMPLE')
               for name in ('public_web','processes_personal_data')})
    profile['facts']['procurement_type'] = dict(state='unknown',owner_ref='author',reason_ref='TASK-CONFIRM-CONTRACT')
    profile_store = profiles.ProjectProfileRegistry.create(root/'profile-registry',trust=trust,**scope)
    def approve_profile(candidate):
        profile_store.apply(sign('profile_action','author',action='revise',profile=candidate,
            expected_revision=candidate['revision']-1),now)
        target = dict(profile_id=candidate['id'],revision=candidate['revision'],profile_digest=c.digest(candidate),expected_revision=candidate['revision'])
        profile_store.apply(sign('profile_action','author',action='submit',**target),now)
        profile_store.apply(sign('profile_approval','approver',decision='approve',reason_ref='PROFILE-REVIEW',
            not_before=now,expires_at=end,**target),now)
    approve_profile(profile)
    registry = packs.RulePackRegistry.create(root/'pack-registry',trust=trust,**scope)
    def feed():
        return registry.issue_revocations(keys['operator']['private_path'],'operator',now=now,expires_at=feed_end,
                                          expected_sequence=registry.checkpoint()['sequence'])
    revocations = feed()
    def action(name, manifest, requirements):
        data = dict(action=name,pack_id=manifest['pack_id'],version=manifest['version'],
                    pack_digest=packs.pack_digest(manifest,requirements),expected_sequence=registry.checkpoint()['sequence'])
        if name=='draft':data.update(manifest=manifest,requirements=requirements)
        if name=='approve':data.update(reason_ref='PACK-REVIEW',not_before=now,expires_at=end)
        if name=='revoke':data.update(reason_ref='SYNTHETIC-REVOCATION-TEST')
        actor = 'approver' if name=='approve' else ('operator' if name=='revoke' else 'author')
        return registry.apply(sign('rule_pack_action',actor,**data),now)
    def publish(manifest, requirements):
        for name in ('draft','submit','approve'):action(name,manifest,requirements)
        return registry.publish(manifest['pack_id'],manifest['version'],keys['operator']['private_path'],'operator',
            now=now,not_before=now,expires_at=end,expected_sequence=registry.checkpoint()['sequence'])
    (delivery,delivery_reqs),(privacy,privacy_reqs) = example_packs(profile,now,end)
    write('delivery-manifest.json',delivery)
    write('delivery-requirements.json',delivery_reqs)
    write('privacy-manifest.json',privacy)
    write('privacy-requirements.json',privacy_reqs)
    releases = [publish(delivery,delivery_reqs),publish(privacy,privacy_reqs)]
    def make_lock(candidate, sequence):
        import uuid
        review_id = uuid.uuid4().hex
        body = dict(common,kind='project_pack_lock',id='LOCK-PROJECT',version=str(sequence),profile_ref=reference(candidate),
            profile_digest=c.digest(candidate),pack_refs=[r['payload']['pack_ref'] for r in releases],policy_bundle_refs=[],
            selection_review_ref=review_id,sequence=sequence,not_before=now,expires_at=end)
        request = sign('pack_selection_request','author',lock=body)
        review = sign('pack_selection_review','approver',request_digest=c.digest(request),decision='approve',
            reason_ref='SELECTION-REVIEW',not_before=now,expires_at=end,event_id=review_id)
        return registry.publish_lock(request,review,releases,profile_store,keys['operator']['private_path'],'operator',
                                    now=now,expected_sequence=registry.checkpoint()['sequence'])
    def assess(lock, reviews=()):
        return applicability.assess(lock,profile_store,trust,now,revocations=revocations,
            expected_revocation_digest=c.digest(revocations),reviews=reviews)
    def exclusion(lock, candidate):
        req = reference(delivery_reqs[0])
        return sign('applicability_review','approver',lock_digest=c.digest(lock),profile_digest=c.digest(candidate),
            requirement_ref=req,subject_digest=applicability.review_subject(c.digest(lock),c.digest(candidate),req,**scope),
            decision='not_applicable',reason_ref='SYNTHETIC-NONWEB-REVIEW',not_before=now,expires_at=end)
    first_lock = make_lock(profile,1)
    initial = assess(first_lock)
    first_review = exclusion(first_lock,profile)
    reviewed = assess(first_lock,[first_review])
    write('lock-v1.json',first_lock)
    write('applicability-initial.json',initial)
    write('applicability-reviewed.json',reviewed)
    revised = _copy(profile)
    revised.update(revision=2,parent_digest=c.digest(profile))
    revised['facts']['procurement_type'] = dict(state='known',value_type='string',value=source['procurement_type'],source_ref='SRC-EXAMPLE')
    approve_profile(revised)
    current_lock = make_lock(revised,2)
    stale_lock,stale_review = False,False
    try:
        assess(first_lock,[first_review])
    except applicability.ApplicabilityError:
        stale_lock = True
    try:
        assess(current_lock,[first_review])
    except applicability.ApplicabilityError:
        stale_review = True
    current_review = exclusion(current_lock,revised)
    # Revoke an actual separate canary pack; keep the two selected packs usable.
    canary = _copy(delivery)
    canary.update(pack_id='PACK-REVOCATION-CANARY')
    canary_release = publish(canary,delivery_reqs)
    action('revoke',canary,delivery_reqs)
    revocations = feed()
    revoked_rejected = False
    try:
        packs.verify_release(canary_release,trust,now=now,revocations=revocations,
            expected_revocation_digest=c.digest(revocations),**scope)
    except packs.PackError:
        revoked_rejected = True
    final = assess(current_lock,[current_review])
    verified = packs.verify_lock(current_lock,trust,now=now,revocations=revocations,profile_registry=profile_store,
                                 expected_revocation_digest=c.digest(revocations),**scope)
    for name,value in [('profile-v1.json',profile),('profile-v2.json',revised),('pack-lock.json',current_lock),
                       ('applicability-review.json',current_review),('revocations.json',revocations),('public-trust.json',trust),
                       ('profile-checkpoint.json',profile_store.checkpoint()),('pack-checkpoint.json',registry.checkpoint()),
                       ('revocation-anchor.json',dict(epoch=revocations['payload']['epoch'],digest=c.digest(revocations))),
                       ('applicability-final.json',final)]:write(name,value)
    checks = dict(signed_lock_verified=verified['profile_digest']==c.digest(revised),
        unknown_requires_review=initial['counts']['pending']==2 and reviewed['counts']['pending']==1,
        exclusion_independent=reviewed['counts']['not_applicable']==1,stale_lock_rejected=stale_lock,
        stale_review_rejected=stale_review,revoked_pack_rejected=revoked_rejected,
        applicability_is_not_fulfillment=final['outcome']=='applicability_resolved' and final['requirements_evaluated'] is False)
    packs._require(all(checks.values()),'PACK_DEMO_INCOMPLETE')
    result = dict(kind='rule_pack_reference_demo',context=security.CONTEXT,operational_approval=False,
        requirements_evaluated=False,initial_counts=initial['counts'],after_review_counts=reviewed['counts'],
        final_counts=final['counts'],active_profile_revision=2,lock_sequence=2,revocation_epoch=revocations['payload']['epoch'],checks=checks)
    write('pack-demo-result.json',result)
    return result


def _copy(value):
    return json.loads(security.canonical(value))
