"""Synthetic authorities shared by R7-C/D tests, not operational approvals."""
import copy
import json
from pathlib import Path

from govcode_harness import security, project_contracts as c, project_profile as profiles
from govcode_harness import rule_pack as packs

NOW = '2026-10-29T00:00:00Z'
END = '2026-11-29T00:00:00Z'
FEED_END = '2026-10-29T01:00:00Z'
FIXTURES = Path(__file__).parent / 'fixtures/project-compliance'


def reference(value):
    return dict(kind=value['kind'],id=value.get('id',value.get('pack_id')),
                version=str(value.get('revision',value.get('version'))),digest=c.digest(value))


class Authority:
    def __init__(self, root):
        self.root = root
        self.counter = 0
        self.keys = {}
        self.trust = dict(context=security.CONTEXT,keys={})
        self.common = dict(schema_version='1',context=security.CONTEXT,tenant_id='t',project_id='p',operational_approval=False)
        for key, actor, roles in [('alice','alice',['author','approver']),('alice2','alice',['approver']),
                                  ('bob','bob',['approver']),('ops','ops',['operator']),('ops2','ops2',['operator'])]:
            item = security.generate_keypair(root/key,key)
            self.keys[key] = item
            self.trust['keys'][key] = dict(public_key=item['public_key'],actor_id=actor,roles=roles,
                                          tenant_id='t',project_id='p',revoked=False)
        self.profile = json.loads((FIXTURES/'profile.example.json').read_text())
        self.profiles = profiles.ProjectProfileRegistry.create(root/'profiles','t','p',self.trust)
        self.approve_profile(self.profile)
        self.registry = packs.RulePackRegistry.create(root/'packs','t','p',self.trust)
        self.feed = self.issue_feed()
        self.manifest, self.requirements = self.make_pack()

    def event(self):
        self.counter += 1
        return f'cd-event-{self.counter}'

    def signed(self, kind, actor, **fields):
        payload = dict(self.common,kind=kind,actor_id=self.trust['keys'][actor]['actor_id'],
                       event_id=self.event(),created_at=NOW)
        payload.update(fields)
        return security.sign(payload,self.keys[actor]['private_path'],actor)

    def approve_profile(self, profile):
        revision = profile['revision']
        payload = self.signed('profile_action','alice',action='revise',profile=profile,expected_revision=revision-1)
        self.profiles.apply(payload,NOW)
        target = dict(profile_id=profile['id'],revision=revision,profile_digest=c.digest(profile),expected_revision=revision)
        self.profiles.apply(self.signed('profile_action','alice',action='submit',**target),NOW)
        self.profiles.apply(self.signed('profile_approval','bob',decision='approve',reason_ref='PROFILE-REVIEW',
                                       not_before=NOW,expires_at=END,**target),NOW)
        self.profile = copy.deepcopy(profile)

    def make_pack(self, pack_id='PACK-DELIVERY', req_id='REQ-DEL-001', expression=None):
        values = json.loads((FIXTURES/'contract-set.example.json').read_text())
        manifest = next(x for x in values if x['kind']=='rule_pack_manifest')
        requirement = next(x for x in values if x['kind']=='requirement_spec')
        manifest.update(pack_id=pack_id)
        requirement['id'] = req_id
        if expression is not None:
            requirement['applicability_expr'] = expression
        manifest['requirement_refs'] = [reference(requirement)]
        return manifest,[requirement]

    def action(self, name, manifest=None, requirements=None, actor=None, **overrides):
        manifest = manifest or self.manifest
        requirements = self.requirements if requirements is None else requirements
        actor = actor or {'draft':'alice','submit':'alice','approve':'bob','reject':'bob','retire':'ops','revoke':'ops'}[name]
        fields = dict(action=name,pack_id=manifest['pack_id'],version=manifest['version'],
                      pack_digest=packs.pack_digest(manifest,requirements),expected_sequence=self.registry.checkpoint()['sequence'])
        if name=='draft':
            fields.update(manifest=manifest,requirements=requirements)
        if name=='approve':
            fields.update(not_before=NOW,expires_at=END,reason_ref='PACK-REVIEW')
        if name in ('reject','retire','revoke'):
            fields['reason_ref']='PACK-REASON'
        fields.update(overrides)
        return self.signed('rule_pack_action',actor,**fields)

    def apply(self, name, **fields):
        return self.registry.apply(self.action(name,**fields),NOW)

    def publish(self, manifest=None, requirements=None):
        manifest = manifest or self.manifest
        requirements = self.requirements if requirements is None else requirements
        manifest['requirement_refs']=[reference(x) for x in requirements]
        for action in ('draft','submit','approve'):
            self.apply(action,manifest=manifest,requirements=requirements)
        return self.registry.publish(manifest['pack_id'],manifest['version'],self.keys['ops']['private_path'],'ops',
            now=NOW,not_before=NOW,expires_at=END,expected_sequence=self.registry.checkpoint()['sequence'])

    def issue_feed(self, actor='ops', **changes):
        return self.registry.issue_revocations(self.keys[actor]['private_path'],actor,now=NOW,
            expires_at=FEED_END,expected_sequence=self.registry.checkpoint()['sequence'],**changes)

    def selection(self, releases, *, sequence=1, profile=None, reviewer='bob'):
        profile = profile or self.profile
        review_id = self.event()
        lock = dict(self.common,kind='project_pack_lock',id='LOCK-DELIVERY',version=str(sequence),
            profile_ref=reference(profile),profile_digest=c.digest(profile),pack_refs=[r['payload']['pack_ref'] for r in releases],
            policy_bundle_refs=[],selection_review_ref=review_id,sequence=sequence,not_before=NOW,expires_at=END)
        request = self.signed('pack_selection_request','alice',lock=lock)
        review = self.signed('pack_selection_review',reviewer,request_digest=c.digest(request),decision='approve',
                             reason_ref='SELECTION-REVIEW',not_before=NOW,expires_at=END,event_id=review_id)
        return request,review

    def lock(self, releases, **options):
        request,review = self.selection(releases,**options)
        return self.registry.publish_lock(request,review,releases,self.profiles,self.keys['ops']['private_path'],'ops',
            now=NOW,expected_sequence=self.registry.checkpoint()['sequence'])

    def verify_release(self, release, **options):
        args=dict(revocations=self.feed,min_sequence=1,min_revocation_epoch=1,expected_revocation_digest=c.digest(self.feed))
        args.update(options)
        return packs.verify_release(release,self.trust,'t','p',NOW,**args)

    def verify_lock(self, lock, **options):
        args=dict(revocations=self.feed,profile_registry=self.profiles,min_sequence=1,min_revocation_epoch=1,expected_revocation_digest=c.digest(self.feed))
        args.update(options)
        return packs.verify_lock(lock,self.trust,'t','p',NOW,**args)
