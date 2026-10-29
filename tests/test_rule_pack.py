import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import rule_pack as packs, project_contracts as c, security
from tests.rule_pack_fixtures import Authority,NOW,END,reference


class RulePackTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.a=Authority(Path(self.tmp.name))

    def test_actual_signed_publication_and_pinned_lock(self):
        release=self.a.publish()
        result=self.a.verify_release(release)
        self.assertEqual(self.a.manifest,result['manifest'])
        self.assertFalse(result['operational_approval'])
        self.assertEqual('published',self.a.registry.get('PACK-DELIVERY','1')['state'])
        lock=self.a.lock([release])
        result=self.a.verify_lock(lock)
        self.assertEqual(c.digest(self.a.profile),result['profile_digest'])
        self.assertEqual(1,len(result['requirements']))

    def test_unapproved_or_unsigned_pack_cannot_publish(self):
        self.a.apply('draft')
        with self.assertRaises(packs.PackError):
            self.a.registry.publish('PACK-DELIVERY','1',self.a.keys['ops']['private_path'],'ops',
                now=NOW,not_before=NOW,expires_at=END,expected_sequence=self.a.registry.checkpoint()['sequence'])
        with self.assertRaises(packs.PackError):
            self.a.registry.apply(self.a.action('submit')['payload'],NOW)

    def test_same_person_with_another_key_cannot_approve(self):
        self.a.apply('draft');self.a.apply('submit')
        with self.assertRaises(packs.PackError) as error:
            self.a.apply('approve',actor='alice2')
        self.assertEqual('SELF_APPROVAL',error.exception.code)

    def test_immutable_version_replay_and_stale_sequence(self):
        action=self.a.action('draft');self.a.registry.apply(action,NOW)
        with self.assertRaises(packs.PackError):self.a.registry.apply(action,NOW)
        with self.assertRaises(packs.PackError):self.a.apply('draft')
        with self.assertRaises(packs.PackError):self.a.apply('submit',expected_sequence=0)

    def test_roles_scope_and_digest_are_not_client_claims(self):
        self.a.apply('draft');self.a.apply('submit')
        for fields in [dict(actor='ops'),dict(pack_digest='f'*64)]:
            with self.assertRaises(packs.PackError):self.a.apply('approve',**fields)
        payload=self.a.action('approve')['payload'];payload['project_id']='foreign'
        with self.assertRaises(packs.PackError):
            self.a.registry.apply(security.sign(payload,self.a.keys['bob']['private_path'],'bob'),NOW)

    def test_tampered_signature_and_wrong_protocol_rejected(self):
        release=self.a.publish();bad=copy.deepcopy(release)
        bad['payload']['sequence']=100
        with self.assertRaises(packs.PackError):self.a.verify_release(bad)
        bad=copy.deepcopy(release);bad['payload']['kind']='policy_bundle'
        bad=security.sign(bad['payload'],self.a.keys['ops']['private_path'],'ops')
        with self.assertRaises(packs.PackError):self.a.verify_release(bad)

    def test_expiry_and_publication_sequence_floor(self):
        release=self.a.publish()
        with self.assertRaises(packs.PackError):self.a.verify_release(release,min_sequence=2)
        with self.assertRaises(packs.PackError):
            packs.verify_release(release,self.a.trust,'t','p',END,revocations=self.a.feed,expected_revocation_digest=c.digest(self.a.feed))

    def test_revocation_feed_is_required_signed_and_fresh(self):
        release=self.a.publish()
        with self.assertRaises(packs.PackError):self.a.verify_release(release,revocations=None)
        bad=copy.deepcopy(self.a.feed);bad['payload']['epoch']=99
        with self.assertRaises(packs.PackError):self.a.verify_release(release,revocations=bad)
        with self.assertRaises(packs.PackError):self.a.verify_release(release,min_revocation_epoch=2)

    def test_revoked_author_approver_and_publisher_keys_block_release(self):
        release=self.a.publish()
        for key in ['alice','bob','ops']:
            self.a.feed=self.a.issue_feed(actor='ops2',key_ids=[key])
            with self.assertRaises(packs.PackError):self.a.verify_release(release)

    def test_revoked_approval_or_release_digest_blocks_release(self):
        release=self.a.publish()
        approval=release['payload']['approval_record']
        self.a.feed=self.a.issue_feed(approval_digests=[c.digest(approval)])
        with self.assertRaises(packs.PackError):self.a.verify_release(release)
        self.a.feed=self.a.issue_feed(release_digests=[c.digest(release)])
        with self.assertRaises(packs.PackError):self.a.verify_release(release)

    def test_pack_revoke_propagates_to_new_feed_and_cannot_be_removed(self):
        release=self.a.publish();old=self.a.feed
        self.a.apply('revoke');self.a.feed=self.a.issue_feed()
        with self.assertRaises(packs.PackError):self.a.verify_release(release)
        with self.assertRaises(packs.PackError):self.a.verify_release(release,revocations=old,min_revocation_epoch=2)
        self.a.feed=self.a.issue_feed()
        with self.assertRaises(packs.PackError):self.a.verify_release(release)

    def test_dependencies_are_complete_and_revocation_is_transitive(self):
        first=self.a.publish()
        manifest,reqs=self.a.make_pack('PACK-OTHER','REQ-OTHER')
        manifest['dependencies']=[reference(self.a.manifest)]
        second=self.a.publish(manifest,reqs)
        with self.assertRaises(packs.PackError):self.a.lock([second])
        lock=self.a.lock([first,second]);self.a.verify_lock(lock)
        self.a.apply('revoke');self.a.feed=self.a.issue_feed()
        with self.assertRaises(packs.PackError):self.a.verify_lock(lock)

    def test_dependency_cycles_and_conflicting_requirements_rejected(self):
        one,req1=self.a.make_pack('PACK-ONE','REQ-SHARED')
        two,req2=self.a.make_pack('PACK-TWO','REQ-SHARED')
        one['dependencies']=[reference(two)];two['dependencies']=[reference(one)]
        with self.assertRaises(packs.PackError):packs.dependency_order([one,two])
        one['dependencies']=[];two['dependencies']=[]
        req2[0]['applicability_expr']['value']['value']=True
        a=self.a.publish(one,req1);b=self.a.publish(two,req2)
        with self.assertRaises(packs.PackError):self.a.lock([a,b])

    def test_identical_shared_requirement_is_counted_once(self):
        first=self.a.publish()
        manifest,reqs=self.a.make_pack('PACK-OTHER')
        second=self.a.publish(manifest,reqs)
        result=self.a.verify_lock(self.a.lock([first,second]))
        self.assertEqual(1,len(result['requirements']))

    def test_selection_is_independently_approved_and_exactly_bound(self):
        release=self.a.publish()
        request,review=self.a.selection([release],reviewer='alice2')
        with self.assertRaises(packs.PackError):
            self.a.registry.publish_lock(request,review,[release],self.a.profiles,self.a.keys['ops']['private_path'],'ops',
                now=NOW,expected_sequence=self.a.registry.checkpoint()['sequence'])
        lock=self.a.lock([release]);bad=copy.deepcopy(lock['payload'])
        bad['lock']['sequence']=2
        with self.assertRaises(packs.PackError):
            self.a.verify_lock(security.sign(bad,self.a.keys['ops']['private_path'],'ops'))

    def test_new_profile_approval_invalidates_old_lock_without_fallback(self):
        release=self.a.publish();lock=self.a.lock([release])
        profile=copy.deepcopy(self.a.profile);profile.update(revision=2,parent_digest=c.digest(self.a.profile))
        self.a.approve_profile(profile)
        with self.assertRaises(packs.PackError):self.a.verify_lock(lock)

    def test_lock_sequence_floor_and_lock_digest_revocation(self):
        lock=self.a.lock([self.a.publish()])
        with self.assertRaises(packs.PackError):self.a.verify_lock(lock,min_sequence=2)
        self.a.feed=self.a.issue_feed(lock_digests=[c.digest(lock)])
        with self.assertRaises(packs.PackError):self.a.verify_lock(lock)

    def test_pending_sources_and_undetermined_force_cannot_publish(self):
        self.a.requirements[0].update(basis_kind='unverified_requirement',source_verification='pending',normativity='undetermined')
        self.a.requirements[0]['source_ref'].update(verification='pending',digest=None)
        self.a.manifest['source_refs']=copy.deepcopy([self.a.requirements[0]['source_ref']])
        self.a.manifest['requirement_refs']=[reference(self.a.requirements[0])]
        self.a.apply('draft');self.a.apply('submit')
        with self.assertRaises(packs.PackError):self.a.apply('approve')

    def test_pack_cannot_embed_executable_commands(self):
        bad=copy.deepcopy(self.a.manifest);bad['command']=['python','untrusted']
        with self.assertRaises(packs.PackError):packs.validate_pack(bad,self.a.requirements)

    def test_checkpoint_detects_truncated_or_modified_history(self):
        self.a.publish();checkpoint=self.a.registry.checkpoint()
        files=sorted((self.a.root/'packs/events').glob('*.json'));files[-1].unlink()
        with self.assertRaises(packs.PackError):
            packs.RulePackRegistry(self.a.root/'packs',self.a.trust,checkpoint=checkpoint)

    def test_trusted_revocation_digest_blocks_a_forged_higher_epoch(self):
        release=self.a.publish()
        self.a.feed=self.a.issue_feed(actor='ops2',key_ids=['ops'])
        forged=copy.deepcopy(self.a.feed['payload'])
        forged.update(actor_id='ops',epoch=forged['epoch']+1,key_ids=[],event_id='forged-new-feed')
        envelope=security.sign(forged,self.a.keys['ops']['private_path'],'ops')
        with self.assertRaises(packs.PackError):
            self.a.verify_release(release,revocations=envelope)

    def test_revocation_anchor_is_required_for_offline_verification(self):
        with self.assertRaises(packs.PackError):
            packs.verify_revocations(self.a.feed,self.a.trust,'t','p',NOW)

    def test_expired_pack_and_lock_are_checked_with_a_fresh_feed(self):
        release=self.a.publish();lock=self.a.lock([release])
        future='2026-11-29T00:00:00Z'
        feed=self.a.registry.issue_revocations(self.a.keys['ops']['private_path'],'ops',now=future,
            expires_at='2026-11-29T01:00:00Z',expected_sequence=self.a.registry.checkpoint()['sequence'])
        for function,value,options in [(packs.verify_release,release,{}),(packs.verify_lock,lock,dict(profile_registry=self.a.profiles))]:
            with self.assertRaises(packs.PackError) as error:
                function(value,self.a.trust,'t','p',future,revocations=feed,expected_revocation_digest=c.digest(feed),**options)
            self.assertEqual('VALIDITY_EXPIRED',error.exception.code)

    def test_feed_window_and_sticky_revocations(self):
        with self.assertRaises(packs.PackError):
            self.a.registry.issue_revocations(self.a.keys['ops']['private_path'],'ops',now=NOW,
                expires_at=END,expected_sequence=self.a.registry.checkpoint()['sequence'])
        self.a.feed=self.a.issue_feed(key_ids=['alice'])
        renewed=self.a.issue_feed(key_ids=[])
        self.assertIn('alice',renewed['payload']['key_ids'])

    def test_retirement_blocks_new_locks_even_before_feed_refresh(self):
        release=self.a.publish();self.a.apply('retire')
        with self.assertRaises(packs.PackError):self.a.lock([release])

    def test_selection_review_and_profile_approval_can_be_revoked(self):
        lock=self.a.lock([self.a.publish()])
        review=lock['payload']['review_record']
        self.a.feed=self.a.issue_feed(review_digests=[c.digest(review)])
        with self.assertRaises(packs.PackError):self.a.verify_lock(lock)

    def test_lock_does_not_trust_a_profile_object_with_stale_keys(self):
        lock=self.a.lock([self.a.publish()])
        trust=copy.deepcopy(self.a.trust);trust['keys']['bob']['revoked']=True
        with self.assertRaises(packs.PackError):
            packs.verify_lock(lock,trust,'t','p',NOW,revocations=self.a.feed,profile_registry=self.a.profiles,
                expected_revocation_digest=c.digest(self.a.feed))

    def test_unknown_dependency_digest_does_not_publish_a_partial_release(self):
        self.a.publish()
        manifest,reqs=self.a.make_pack('PACK-OTHER','REQ-OTHER')
        manifest['dependencies']=[dict(reference(self.a.manifest),digest='f'*64)]
        with self.assertRaises(packs.PackError):self.a.publish(manifest,reqs)
        self.assertEqual('approved',self.a.registry.get('PACK-OTHER','1')['state'])

    def test_history_budget_failure_is_atomic(self):
        before=self.a.registry.checkpoint()
        used=sum(p.stat().st_size for p in (self.a.root/'packs/events').glob('*.json'))
        with patch.object(packs,'MAX_HISTORY_BYTES',used+1):
            with self.assertRaises(packs.PackError):self.a.apply('draft')
        self.assertEqual(before,self.a.registry.checkpoint())


if __name__ == '__main__':unittest.main()
