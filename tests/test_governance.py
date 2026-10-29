import copy
import tempfile
import unittest
from pathlib import Path
from govcode_harness import security, governance

NOW = '2026-10-28T00:00:00Z'
END = '2026-10-29T00:00:00Z'


class GovernanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir='/private/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.keys = {}
        self.trust = {'context': 'synthetic_reference', 'keys': {}}
        for actor, role in [('alice', 'author'), ('bob', 'approver'), ('ops', 'operator')]:
            key = security.generate_keypair(self.root / actor, actor)
            self.keys[actor] = key
            self.trust['keys'][actor] = dict(public_key=key['public_key'], actor_id=actor, roles=[role], tenant_id='t', project_id='p', revoked=False)
        self.registry = governance.PolicyRegistry.create(self.root / 'registry', 't', 'p', self.trust)
        self.policy = {'id': 'P1', 'version': '1', 'basis_kind': 'example_policy', 'scope': {'tenant_id': 't', 'project_id': 'p', 'languages': ['python'], 'stage': 'merge'}, 'condition': {'field': 'finding.category', 'operator': 'eq', 'value': 'sensitive_logging'}, 'effect': 'deny'}
        self.nonce = 0

    def signed(self, actor, payload):
        self.nonce += 1
        common = dict(context='synthetic_reference', tenant_id='t', project_id='p', actor_id=actor, event_id=f'event-{self.nonce}', created_at=NOW)
        common.update(payload)
        return security.sign(common, self.keys[actor]['private_path'], actor)

    def action(self, action, actor=None, **extra):
        actor = actor or {'draft': 'alice', 'submit': 'alice', 'approve': 'bob', 'retire': 'ops', 'revoke': 'ops'}[action]
        payload = dict(action=action)
        if action == 'draft': payload.update(policy=self.policy, obligations=[])
        else: payload.update(policy_id='P1', version='1', policy_digest=governance.digest(self.policy))
        payload.update(extra)
        return self.signed(actor, payload)

    def approved(self):
        for action in ('draft', 'submit', 'approve'): self.registry.apply(self.action(action), NOW)

    def bundle(self, **kwargs):
        options = dict(not_before=NOW, expires_at=END, sequence=1)
        options.update(kwargs)
        return self.registry.issue_bundle([{'id': 'P1', 'version': '1'}], self.keys['ops']['private_path'], 'ops', **options)

    def validate(self, bundle, **kwargs):
        return governance.validate_bundle(bundle, self.trust, 't', 'p', NOW, **kwargs)

    def test_lifecycle_persistence_and_bundle_proofs(self):
        self.approved()
        self.registry = governance.PolicyRegistry(self.root / 'registry', self.trust)
        result = self.validate(self.bundle())
        self.assertFalse(result['operational_approval'])
        self.assertEqual(self.policy, result['policies'][0]['policy'])
        self.assertEqual(governance.digest(self.policy), result['policies'][0]['policy_digest'])

    def test_transitions_replay_immutability_and_hash_chain(self):
        draft = self.action('draft')
        self.registry.apply(draft, NOW)
        for action in (draft, self.action('approve'), self.action('draft')):
            with self.assertRaises(governance.GovernanceError): self.registry.apply(action, NOW)
        self.registry.apply(self.action('submit'), NOW)
        changed = self.action('approve', policy_digest='0' * 64)
        with self.assertRaises(governance.GovernanceError): self.registry.apply(changed, NOW)
        self.registry.apply(self.action('approve'), NOW)
        event = next((self.root / 'registry' / 'events').glob('*.json'))
        event.write_text('{}')
        with self.assertRaises(governance.GovernanceError): governance.PolicyRegistry(self.root / 'registry', self.trust)

    def test_self_approval_and_unknown_expression_rejected(self):
        self.trust['keys']['alice']['roles'].append('approver')
        self.registry = governance.PolicyRegistry(self.root / 'registry', self.trust)
        self.registry.apply(self.action('draft'), NOW)
        self.registry.apply(self.action('submit'), NOW)
        with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('approve', actor='alice'), NOW)
        for field, value in [('field', 'arbitrary.code'), ('operator', 'exec')]:
            self.policy['version'] += 'x'
            self.policy['condition'][field] = value
            with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('draft'), NOW)

    def test_offline_expiry_rollback_tamper_and_revocations(self):
        self.approved()
        bundle = self.bundle()
        with self.assertRaises(governance.GovernanceError): self.validate(bundle, min_sequence=2)
        with self.assertRaises(governance.GovernanceError): governance.validate_bundle(bundle, self.trust, 't', 'p', END)
        tampered = copy.deepcopy(bundle)
        tampered['payload']['policies'][0]['policy']['effect'] = 'allow'
        with self.assertRaises(governance.GovernanceError): self.validate(tampered)
        for fields in ({'bundle_digests': [governance.digest(bundle['payload'])]}, {'key_ids': ['alice']}, {'policy_digests': [governance.digest(self.policy)]}, {'epoch': 2}):
            rev = dict(kind='policy_revocations', epoch=0, bundle_digests=[], key_ids=[], policy_digests=[])
            rev.update(fields)
            with self.assertRaises(governance.GovernanceError): self.validate(bundle, revocations=self.signed('ops', rev))
        self.registry.apply(self.action('revoke'), NOW)
        with self.assertRaises(governance.GovernanceError): self.bundle()

    def test_missing_pending_and_ambiguous_statutory_basis(self):
        self.policy['basis_kind'] = 'statutory_obligation'
        for obligation in (None, {'status': 'PENDING'}, {'status': 'VERIFIED', 'applicability': 'CONDITIONAL'}):
            with self.subTest(obligation=obligation):
                obligations = [] if obligation is None else [obligation]
                with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('draft', obligations=obligations), NOW)

    def test_verified_synthetic_basis_effective_interval(self):
        self.policy['basis_kind'] = 'statutory_obligation'
        basis = {'id': 'O1', 'status': 'VERIFIED', 'applicability': 'APPLICABLE', 'source_id': 'S1', 'source_version': '1', 'source_digest': 'a' * 64, 'effective_from': NOW, 'effective_to': END}
        self.registry.apply(self.action('draft', obligations=[basis]), NOW)
        for action in ('submit', 'approve'): self.registry.apply(self.action(action), NOW)
        self.validate(self.bundle())
        with self.assertRaises(governance.GovernanceError): self.bundle(expires_at='2026-10-30T00:00:00Z')

    def exception_context(self):
        run = {'commit_sha': '1' * 40, 'tool_digest': '2' * 64, 'tenant_id': 't', 'project_id': 'p'}
        finding = {'id': 'F1', 'run_id': 'old-run', 'detector_id': 'python-local-flow', 'detector_version': '1', 'category': 'sensitive_logging', 'severity': 'high', 'location': {'path': 'api.py', 'line': 4}, 'data_classes': ['request_body']}
        return run, finding

    def exception_pair(self, *, request_changes=None):
        run, finding = self.exception_context()
        context = dict(commit_sha=run['commit_sha'], tool_digest=run['tool_digest'], finding_digests={'F1': governance.finding_digest(run, finding, self.policy)})
        payload = dict(kind='exception_request', policy_id='P1', version='1', policy_digest=governance.digest(self.policy), finding_ids=['F1'], compensating_control='Synthetic additional review', expires_at=END, **context)
        payload.update(request_changes or {})
        request = self.signed('alice', payload)
        approval = self.signed('bob', {'kind': 'exception_approval', 'request': request})
        return request, approval, context

    def test_exception_independent_scope_expiry_and_statutory_boundary(self):
        request, approval, context = self.exception_pair()
        self.assertEqual(['F1'], governance.validate_exception(approval, self.trust, self.policy, ['F1', 'F2'], NOW, **dict(context, finding_digests={**context['finding_digests'], 'F2': '3' * 64})))
        for findings, when, policy in [(['F2'], NOW, self.policy), (['F1'], END, self.policy), (['F1'], NOW, dict(self.policy, basis_kind='statutory_obligation'))]:
            with self.assertRaises(governance.GovernanceError): governance.validate_exception(approval, self.trust, policy, findings, when, **context)
        self.trust['keys']['alice']['roles'].append('approver')
        self_approval = self.signed('alice', {'kind': 'exception_approval', 'request': request})
        with self.assertRaises(governance.GovernanceError): governance.validate_exception(self_approval, self.trust, self.policy, ['F1'], NOW, **context)

    def test_record_revocation_and_signed_revocation_scope(self):
        self.approved()
        bundle = self.bundle()
        author = bundle['payload']['policies'][0]['author_record']
        rev = self.signed('ops', dict(kind='policy_revocations', epoch=0, bundle_digests=[], key_ids=[], policy_digests=[], record_digests=[governance.digest(author)]))
        with self.assertRaises(governance.GovernanceError) as caught: self.validate(bundle, revocations=rev)
        self.assertEqual('RECORD_REVOKED', caught.exception.code)

    def test_event_time_order_and_current_registry_clock(self):
        self.registry.apply(self.action('draft'), NOW)
        submit = self.action('submit', created_at='2026-10-27T00:00:00Z')
        with self.assertRaises(governance.GovernanceError) as caught: self.registry.apply(submit, NOW)
        self.assertEqual('EVENT_TIME_ORDER', caught.exception.code)
        self.registry.apply(self.action('submit'), NOW)
        with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('approve'), '2026-10-27T00:00:00Z')

    def test_atomic_failed_append_can_retry(self):
        from unittest.mock import patch
        draft = self.action('draft')
        with patch.object(governance, '_write_new', side_effect=OSError('sensitive raw error')):
            with self.assertRaises(governance.GovernanceError) as caught: self.registry.apply(draft, NOW)
        self.assertNotIn('sensitive', str(caught.exception))
        self.assertEqual([], list((self.root / 'registry' / 'events').glob('*.json')))
        self.assertEqual('draft', self.registry.apply(draft, NOW)['state'])

    def test_wrong_scope_key_revocation_empty_future_and_unapproved(self):
        with self.assertRaises(governance.GovernanceError): self.bundle()
        self.approved()
        with self.assertRaises(governance.GovernanceError): self.registry.issue_bundle([], self.keys['ops']['private_path'], 'ops', NOW, END, 1)
        bundle = self.bundle()
        for when in ('2026-10-27T00:00:00Z', END):
            with self.assertRaises(governance.GovernanceError): governance.validate_bundle(bundle, self.trust, 't', 'p', when)
        with self.assertRaises(governance.GovernanceError): governance.validate_bundle(bundle, self.trust, 'other', 'p', NOW)
        self.trust['keys']['alice']['revoked'] = True
        with self.assertRaises(governance.GovernanceError): self.validate(bundle)

    def test_re_signed_outer_bundle_cannot_change_approved_body(self):
        self.approved()
        bundle = self.bundle()
        payload = bundle['payload']
        payload['policies'][0]['policy']['condition']['value'] = 'other_category'
        payload['policies'][0]['policy_digest'] = governance.digest(payload['policies'][0]['policy'])
        bundle = security.sign(payload, self.keys['ops']['private_path'], 'ops')
        with self.assertRaises(governance.GovernanceError): self.validate(bundle)

    def test_retired_policy_cannot_issue_or_reapprove(self):
        self.approved()
        self.assertEqual('retired', self.registry.apply(self.action('retire'), NOW)['state'])
        with self.assertRaises(governance.GovernanceError): self.bundle()
        with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('approve'), NOW)

    def test_unknown_scope_effect_and_ambiguous_source_window(self):
        original = copy.deepcopy(self.policy)
        for change in ('stage', 'language', 'effect', 'unknown'):
            self.policy = copy.deepcopy(original)
            if change == 'stage': self.policy['scope']['stage'] = 'production_request'
            if change == 'language': self.policy['scope']['languages'] = ['javascript']
            if change == 'effect': self.policy['effect'] = 'allow'
            if change == 'unknown': self.policy['expression'] = 'run arbitrary code'
            with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('draft'), NOW)
        self.policy = dict(original, basis_kind='statutory_obligation')
        basis = {'id': 'O1', 'status': 'VERIFIED', 'applicability': 'APPLICABLE', 'source_id': 'S1', 'source_version': '1', 'source_digest': 'a' * 64, 'effective_from': NOW, 'effective_to': None}
        with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('draft', obligations=[basis]), NOW)

    def test_ambiguous_timestamp_rejected(self):
        self.registry.apply(self.action('draft'), NOW)
        with self.assertRaises(governance.GovernanceError): self.registry.apply(self.action('submit', created_at='20261028T000000Z'), NOW)

    def test_exception_requires_fresh_commit_tool_and_exact_finding_map(self):
        _, approval, context = self.exception_pair()
        with self.assertRaises(governance.GovernanceError): governance.validate_exception(approval, self.trust, self.policy, ['F1'], NOW)
        for altered in (dict(context, commit_sha='4' * 40), dict(context, tool_digest='4' * 64), dict(context, finding_digests={'F1': '4' * 64}), dict(context, finding_digests={}), dict(context, finding_digests={'F1': context['finding_digests']['F1'], 'unknown': '4' * 64})):
            with self.subTest(altered=altered):
                with self.assertRaises(governance.GovernanceError): governance.validate_exception(approval, self.trust, self.policy, ['F1'], NOW, **altered)
        for changed_map in ({}, {'F1': context['finding_digests']['F1'], 'F2': '4' * 64}):
            _, changed, _ = self.exception_pair(request_changes={'finding_digests': changed_map})
            with self.assertRaises(governance.GovernanceError): governance.validate_exception(changed, self.trust, self.policy, ['F1'], NOW, **context)

    def test_exception_revoked_requester_approver_and_both_records(self):
        request, approval, context = self.exception_pair()
        for change in ({'key_ids': ['alice']}, {'key_ids': ['bob']}, {'record_digests': [governance.digest(request)]}, {'record_digests': [governance.digest(approval)]}):
            revocation = dict(kind='policy_revocations', epoch=0, bundle_digests=[], key_ids=[], policy_digests=[], record_digests=[])
            revocation.update(change)
            signed = self.signed('ops', revocation)
            with self.subTest(change=change):
                with self.assertRaises(governance.GovernanceError): governance.validate_exception(approval, self.trust, self.policy, ['F1'], NOW, revocations=signed, **context)
        invalid = self.signed('alice', dict(kind='policy_revocations', epoch=0, bundle_digests=[], key_ids=[], policy_digests=[]))
        with self.assertRaises(governance.GovernanceError): governance.validate_exception(approval, self.trust, self.policy, ['F1'], NOW, revocations=invalid, **context)

    def test_semantic_finding_digest_excludes_ids_and_binds_all_security_fields(self):
        run, finding = self.exception_context()
        original = governance.finding_digest(run, finding, self.policy)
        self.assertEqual(original, governance.finding_digest(dict(run, id='new-run'), dict(finding, id='new-finding', run_id='new-run'), self.policy))
        changes = [('detector_id', 'other'), ('detector_version', '2'), ('category', 'other'), ('severity', 'critical'), ('location', {'path': 'other.py', 'line': 4}), ('location', {'path': 'api.py', 'line': 5}), ('data_classes', ['national_identifier'])]
        for field, value in changes:
            self.assertNotEqual(original, governance.finding_digest(run, dict(finding, **{field: value}), self.policy))
        for field, value in [('commit_sha', '3' * 40), ('tool_digest', '3' * 64)]:
            self.assertNotEqual(original, governance.finding_digest(dict(run, **{field: value}), finding, self.policy))
        self.assertNotEqual(original, governance.finding_digest(run, finding, dict(self.policy, version='2')))
        with self.assertRaises(governance.GovernanceError): governance.finding_digest(dict(run, tenant_id='other'), finding, self.policy)
