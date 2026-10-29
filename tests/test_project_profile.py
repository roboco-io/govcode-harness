import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from govcode_harness import security, project_contracts as contracts
from govcode_harness import project_profile as profiles

NOW = '2026-10-29T00:00:00Z'
END = '2026-11-29T00:00:00Z'
FIXTURE = Path(__file__).parent / 'fixtures/project-compliance/profile.example.json'


class ProjectProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = json.loads(FIXTURE.read_text())
        self.trust = {'context': 'synthetic_reference', 'keys': {}}
        self.keys = {}
        for key_id, actor, roles in [('alice', 'alice', ['author']), ('bob', 'bob', ['approver']),
                                     ('ops', 'ops', ['operator']), ('audit', 'audit', ['auditor']),
                                     ('alice2', 'alice', ['approver'])]:
            key = security.generate_keypair(self.root / key_id, key_id)
            self.keys[key_id] = key
            self.trust['keys'][key_id] = dict(public_key=key['public_key'], actor_id=actor,
                roles=roles, tenant_id='t', project_id='p', revoked=False)
        self.registry = profiles.ProjectProfileRegistry.create(self.root / 'profiles', 't', 'p', self.trust)
        self.nonce = 0

    def signed(self, action, *, profile=None, actor=None, revision=1, expected=None, **extra):
        actor = actor or {'revise': 'alice', 'submit': 'alice', 'approve': 'bob', 'reject': 'bob',
                          'retire': 'ops', 'revoke': 'ops'}[action]
        self.nonce += 1
        payload = dict(schema_version='1', context='synthetic_reference', tenant_id='t', project_id='p',
            operational_approval=False, actor_id=self.trust['keys'][actor]['actor_id'],
            event_id=f'evt-{self.nonce}', created_at=NOW,
            expected_revision=(revision - 1 if action == 'revise' else revision) if expected is None else expected)
        if action == 'revise':
            payload.update(kind='profile_action', action=action, profile=profile or self.profile)
        else:
            payload.update(profile_id=self.profile['id'], revision=revision,
                           profile_digest=contracts.digest(profile or self.profile))
            if action in ('approve', 'reject'):
                payload.update(kind='profile_approval', decision=action, reason_ref='REVIEW-REFERENCE')
                if action == 'approve':
                    payload.update(not_before=NOW, expires_at=END)
            else:
                payload.update(kind='profile_action', action=action)
                if action in ('retire', 'revoke'):
                    payload['reason_ref'] = 'REASON-REFERENCE'
        payload.update(extra)
        return security.sign(payload, self.keys[actor]['private_path'], actor)

    def apply(self, action, **options):
        return self.registry.apply(self.signed(action, **options), NOW)

    def approved(self):
        for action in ('revise', 'submit', 'approve'):
            self.apply(action)

    def revision_two(self):
        profile = copy.deepcopy(self.profile)
        profile.update(revision=2, parent_digest=contracts.digest(self.profile))
        profile['facts']['procurement_type'] = dict(state='known', value_type='string',
            value='synthetic_fixed_scope', source_ref='SRC-EXAMPLE')
        return profile

    def test_signed_lifecycle_persists_without_mutating_profile(self):
        self.approved()
        reopened = profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust)
        active = reopened.active(self.profile['id'], NOW)
        self.assertEqual('approved', active['state'])
        self.assertEqual(self.profile, active['profile'])
        self.assertEqual('draft', active['profile']['lifecycle'])
        self.assertFalse(active['operational_approval'])
        active['profile']['facts'].clear()
        self.assertEqual(self.profile, reopened.get(self.profile['id'], 1)['profile'])

    def test_unknown_and_missing_are_not_false_or_automatic_exclusions(self):
        self.approved()
        active = self.registry.active(self.profile['id'], NOW)
        self.assertEqual('approved', active['state'])
        self.assertIs(False, profiles.read_fact(self.profile, 'public_web')['value'])
        self.assertEqual({'state': 'missing'}, profiles.read_fact(self.profile, 'not_supplied'))
        self.assertEqual('unknown', profiles.read_fact(self.profile, 'procurement_type')['state'])
        self.assertEqual('not_applicable', profiles.read_fact(self.profile, 'mobile_app')['state'])
        gaps = profiles.information_gaps(self.profile, ['not_supplied'])
        by_name = {g['fact']: g for g in gaps}
        self.assertNotIn('public_web', by_name)
        self.assertEqual('missing', by_name['not_supplied']['state'])
        self.assertEqual('unknown', by_name['procurement_type']['state'])
        self.assertEqual('review_applicability', by_name['mobile_app']['action'])

    def test_draft_revision_does_not_replace_active_approval(self):
        self.approved()
        two = self.revision_two()
        self.apply('revise', profile=two, revision=2)
        self.assertEqual(1, self.registry.active(self.profile['id'], NOW)['profile']['revision'])
        self.assertEqual('draft', self.registry.get(self.profile['id'])['state'])
        for action in ('submit', 'approve'):
            self.apply(action, profile=two, revision=2)
        self.assertEqual(2, self.registry.active(self.profile['id'], NOW)['profile']['revision'])
        self.assertEqual(self.profile, self.registry.get(self.profile['id'], 1)['profile'])

    def test_revision_parent_and_optimistic_conflict(self):
        self.approved()
        two = self.revision_two()
        bad = copy.deepcopy(two)
        bad['parent_digest'] = 'f' * 64
        with self.assertRaises(profiles.ProfileError):
            self.apply('revise', profile=bad, revision=2)
        self.apply('revise', profile=two, revision=2)
        with self.assertRaises(profiles.ProfileError) as caught:
            self.apply('revise', profile=two, revision=2)
        self.assertEqual('REVISION_CONFLICT', caught.exception.code)

    def test_same_author_other_key_cannot_self_approve(self):
        self.apply('revise')
        self.apply('submit')
        with self.assertRaises(profiles.ProfileError) as caught:
            self.apply('approve', actor='alice2')
        self.assertEqual('SELF_APPROVAL', caught.exception.code)
        self.assertEqual('review', self.registry.get(self.profile['id'])['state'])

    def test_approval_role_and_subject_are_trusted_not_claimed(self):
        self.apply('revise')
        self.apply('submit')
        for actor in ('alice', 'audit'):
            with self.assertRaises(profiles.ProfileError):
                self.apply('approve', actor=actor)
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve', actor_id='another-person')

    def test_approval_binds_exact_revision_and_digest(self):
        self.apply('revise')
        self.apply('submit')
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve', profile_digest='f' * 64)
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve', revision=2)
        self.assertEqual('review', self.registry.get(self.profile['id'])['state'])

    def test_cannot_approve_a_superseded_draft(self):
        self.apply('revise')
        self.apply('submit')
        two = self.revision_two()
        self.apply('revise', profile=two, revision=2)
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve', expected=2)

    def test_cross_tenant_project_and_signature_tampering_rejected(self):
        for fields in ({'tenant_id': 'other'}, {'project_id': 'other'}):
            with self.assertRaises(profiles.ProfileError):
                self.registry.apply(self.signed('revise', **fields), NOW)
        action = self.signed('revise')
        action['payload']['profile']['stage'] = 'operations'
        with self.assertRaises(profiles.ProfileError):
            self.registry.apply(action, NOW)

    def test_other_author_cannot_revise_or_submit(self):
        self.apply('revise')
        trust = copy.deepcopy(self.trust)
        trust['keys']['ops']['roles'].append('author')
        self.registry = profiles.ProjectProfileRegistry(self.root / 'profiles', trust)
        with self.assertRaises(profiles.ProfileError):
            self.apply('submit', actor='ops')
        with self.assertRaises(profiles.ProfileError):
            self.apply('revise', actor='ops', profile=self.revision_two(), revision=2)

    def test_replay_and_out_of_order_events_do_not_write(self):
        action = self.signed('revise')
        self.registry.apply(action, NOW)
        checkpoint = self.registry.checkpoint()
        with self.assertRaises(profiles.ProfileError):
            self.registry.apply(action, NOW)
        with self.assertRaises(profiles.ProfileError):
            self.apply('submit', created_at='2026-10-28T00:00:00Z')
        self.assertEqual(checkpoint, self.registry.checkpoint())

    def test_future_and_expired_approvals_are_rejected(self):
        self.apply('revise')
        self.apply('submit')
        for options in ({'not_before': '2026-10-30T00:00:00Z'},
                        {'expires_at': NOW}, {'created_at': '2026-10-30T00:00:00Z'}):
            with self.assertRaises(profiles.ProfileError):
                self.apply('approve', **options)

    def test_reject_requires_new_revision_and_keeps_old_active(self):
        self.approved()
        two = self.revision_two()
        self.apply('revise', profile=two, revision=2)
        self.apply('submit', profile=two, revision=2)
        self.apply('reject', profile=two, revision=2)
        self.assertEqual('rejected', self.registry.get(self.profile['id'])['state'])
        self.assertEqual(1, self.registry.active(self.profile['id'], NOW)['profile']['revision'])
        with self.assertRaises(profiles.ProfileError):
            self.apply('submit', profile=two, revision=2)

    def test_no_automatic_fallback_after_retirement_revocation_or_expiry(self):
        self.approved()
        two = self.revision_two()
        for action in ('revise', 'submit', 'approve'):
            self.apply(action, profile=two, revision=2)
        with self.assertRaises(profiles.ProfileError):
            self.registry.active(self.profile['id'], END)
        self.apply('retire', profile=two, revision=2)
        with self.assertRaises(profiles.ProfileError):
            self.registry.active(self.profile['id'], NOW)
        self.apply('revoke', profile=two, revision=2)
        with self.assertRaises(profiles.ProfileError):
            self.registry.active(self.profile['id'], NOW)

    def test_min_revision_and_expected_digest_prevent_reusing_old_approval(self):
        self.approved()
        for options in ({'min_revision': 2}, {'expected_profile_digest': '0' * 64}):
            with self.assertRaises(profiles.ProfileError):
                self.registry.active(self.profile['id'], NOW, **options)

    def test_revoked_signer_disallows_current_use(self):
        self.approved()
        trust = copy.deepcopy(self.trust)
        trust['keys']['bob']['revoked'] = True
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry(self.root / 'profiles', trust)

    def test_hash_chain_edit_tail_rollback_and_fork_anchor(self):
        self.approved()
        checkpoint = self.registry.checkpoint()
        events = sorted((self.root / 'profiles/events').glob('*.json'))
        last = events[-1]
        raw = last.read_bytes()
        last.unlink()
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust, checkpoint=checkpoint)
        last.write_bytes(raw)
        data = json.loads(raw)
        data['received_at'] = '2026-10-30T00:00:00Z'
        last.write_text(json.dumps(data))
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust)

    def test_checkpoint_accepts_new_valid_events_after_anchor(self):
        self.apply('revise')
        checkpoint = self.registry.checkpoint()
        for action in ('submit', 'approve'):
            self.apply(action)
        reopened = profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust, checkpoint=checkpoint)
        self.assertEqual('approved', reopened.active(self.profile['id'], NOW)['state'])

    def test_concurrent_expected_revision_has_one_winner(self):
        self.approved()
        actions = [self.signed('revise', profile=self.revision_two(), revision=2) for _ in range(2)]
        def attempt(action):
            try:
                profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust).apply(action, NOW)
                return 'accepted'
            except profiles.ProfileError as error:
                return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, actions))
        self.assertEqual(['REVISION_CONFLICT', 'accepted'], sorted(results))
        self.assertEqual(2, len(self.registry.history(self.profile['id'])))

    def test_store_symlinks_unknown_files_and_existing_root_rejected(self):
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry.create(self.root / 'profiles', 't', 'p', self.trust)
        link = self.root / 'linked'
        link.symlink_to(self.root / 'profiles', target_is_directory=True)
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry(link, self.trust)
        (self.root / 'profiles/events/unexpected.json').write_text('{}')
        with self.assertRaises(profiles.ProfileError):
            self.registry.history(self.profile['id'])

    def test_signed_wrong_protocol_and_unsubmitted_approval_rejected(self):
        self.apply('revise')
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve')
        self.apply('submit')
        with self.assertRaises(profiles.ProfileError):
            self.apply('approve', kind='policy_bundle')

    def test_history_budget_failure_does_not_append_an_unreadable_event(self):
        self.apply('revise')
        before = self.registry.checkpoint()
        used = sum(p.stat().st_size for p in (self.root / 'profiles/events').glob('*.json'))
        with patch.object(profiles, 'MAX_HISTORY_BYTES', used + 1):
            with self.assertRaises(profiles.ProfileError):
                self.apply('submit')
        self.assertEqual(before, self.registry.checkpoint())

    def test_active_rejects_clock_rollback_before_received_approval(self):
        self.apply('revise')
        self.apply('submit')
        later = '2026-10-29T01:00:00Z'
        approval = self.signed('approve', created_at=later)
        self.registry.apply(approval, later)
        with self.assertRaises(profiles.ProfileError):
            self.registry.active(self.profile['id'], NOW)

    def test_fact_helpers_reject_another_contract_kind(self):
        values = json.loads((FIXTURE.parent / 'contract-set.example.json').read_text())
        pack = next(x for x in values if x['kind'] == 'rule_pack_manifest')
        with self.assertRaises(profiles.ProfileError):
            profiles.information_gaps(pack)
        with self.assertRaises(profiles.ProfileError):
            profiles.read_fact(pack, 'public_web')

    def test_checkpoint_is_bound_to_registry_identity(self):
        other = profiles.ProjectProfileRegistry.create(self.root / 'other', 't', 'p', self.trust)
        with self.assertRaises(profiles.ProfileError):
            profiles.ProjectProfileRegistry(self.root / 'profiles', self.trust, checkpoint=other.checkpoint())


if __name__ == '__main__':
    unittest.main()
