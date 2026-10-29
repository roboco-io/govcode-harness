import copy
import json
from pathlib import Path
import tempfile
import unittest

from govcode_harness import project_contracts as contracts

FIXTURES = Path(__file__).parent / 'fixtures/project-compliance'


class ProjectContractTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads((FIXTURES / 'profile.example.json').read_text())

    def invalid(self, value, code=None):
        with self.assertRaises(contracts.ContractError) as caught:
            contracts.validate(value)
        if code:
            self.assertEqual(code, caught.exception.code)

    def test_profile_preserves_unknown_false_and_not_applicable(self):
        result = contracts.validate(self.profile)
        self.assertIs(False, result['facts']['public_web']['value'])
        self.assertNotIn('value', result['facts']['procurement_type'])
        self.assertEqual('not_applicable', result['facts']['mobile_app']['state'])
        result['facts'].clear()
        self.assertEqual(3, len(self.profile['facts']))

    def test_unknown_cannot_hide_a_value(self):
        self.profile['facts']['procurement_type']['value'] = False
        self.invalid(self.profile)

    def test_known_value_requires_a_declared_verified_source(self):
        for change in ('undeclared', 'pending'):
            profile = copy.deepcopy(self.profile)
            if change == 'undeclared':
                profile['facts']['public_web']['source_ref'] = 'missing'
            else:
                profile['source_refs'][0].update(verification='pending', digest=None)
            self.invalid(profile)

    def test_literal_types_do_not_coerce_false_to_zero(self):
        self.profile['facts']['public_web']['value_type'] = 'integer'
        self.invalid(self.profile)

    def test_na_requires_reason_owner_and_source(self):
        for key in ('reason_ref', 'owner_ref', 'source_ref'):
            profile = copy.deepcopy(self.profile)
            del profile['facts']['mobile_app'][key]
            self.invalid(profile)

    def test_unknown_field_and_operational_claims_rejected(self):
        for field, value in [('unexpected', 1), ('operational_approval', True), ('lifecycle', 'approved')]:
            profile = copy.deepcopy(self.profile)
            profile[field] = value
            self.invalid(profile)

    def test_revision_is_positive_integer_and_parent_binding_is_required(self):
        for revision in (0, -1, True, '1'):
            profile = copy.deepcopy(self.profile)
            profile['revision'] = revision
            self.invalid(profile)
        self.profile['revision'] = 2
        self.invalid(self.profile)
        self.profile['parent_digest'] = 'a' * 64
        contracts.validate(self.profile)

    def test_duplicate_source_ids_rejected(self):
        self.profile['source_refs'].append(dict(self.profile['source_refs'][0], version='2'))
        self.invalid(self.profile, 'SOURCE_ID_DUPLICATE')

    def test_unknown_kind_and_nonfinite_json_rejected(self):
        self.invalid(dict(self.profile, kind='policy_bundle'))
        profile = copy.deepcopy(self.profile)
        profile['facts']['public_web']['value'] = float('nan')
        self.invalid(profile)

    def test_load_rejects_duplicate_keys_and_symlink(self):
        with tempfile.TemporaryDirectory(dir='/private/tmp') as tmp:
            path = Path(tmp) / 'input.json'
            path.write_text('{"kind":"project_profile","kind":"project_profile"}')
            with self.assertRaises(contracts.ContractError) as caught:
                contracts.load(path)
            self.assertEqual('JSON_DUPLICATE_KEY', caught.exception.code)
            target = Path(tmp) / 'link.json'
            target.symlink_to(path)
            with self.assertRaises(contracts.ContractError):
                contracts.load(target)

    def test_all_contract_examples_and_their_reference_graph(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        self.assertGreaterEqual(len(values), 12)
        contracts.validate_set(values)

    def test_reference_graph_rejects_missing_digest_conflict_and_scope(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        for mutation in ('missing', 'digest', 'scope', 'duplicate'):
            items = copy.deepcopy(values)
            if mutation == 'missing':
                items = [x for x in items if x['kind'] != 'requirement_spec']
            elif mutation == 'digest':
                next(x for x in items if x['kind'] == 'rule_pack_manifest')['requirement_refs'][0]['digest'] = 'f' * 64
            elif mutation == 'scope':
                items[-1]['project_id'] = 'another-project'
            else:
                items.append(copy.deepcopy(items[0]))
            with self.assertRaises(contracts.ContractError):
                contracts.validate_set(items)

    def test_pack_is_data_not_an_executable_plugin(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        pack = next(x for x in values if x['kind'] == 'rule_pack_manifest')
        for field, value in [('shell', 'echo unsafe'), ('command', ['python', '-c', 'pass'])]:
            self.invalid(dict(pack, **{field: value}))
        pack['check_specs'][0]['adapter_id'] = 'arbitrary-executable'
        self.invalid(pack)

    def test_expression_operator_type_and_depth_limits(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        requirement = next(x for x in values if x['kind'] == 'requirement_spec')
        self.invalid(dict(requirement, applicability_expr={'op': 'eval', 'code': 'true'}))
        expr = requirement['applicability_expr']
        for _ in range(17):
            expr = {'op': 'not', 'arg': expr}
        self.invalid(dict(requirement, applicability_expr=expr), 'EXPRESSION_LIMIT')

    def test_bad_dates_and_traversal_rejected(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        pack = next(x for x in values if x['kind'] == 'rule_pack_manifest')
        self.invalid(dict(pack, expires_at='2026-02-30T00:00:00Z'))
        self.invalid(dict(pack, expires_at=pack['not_before']))
        artifact = next(x for x in values if x['kind'] == 'artifact_ref')
        for path in ('../secret', '/absolute', 'docs/../secret', 'docs\\secret'):
            self.invalid(dict(artifact, relative_path=path))

    def test_self_approval_and_fake_satisfied_assessment_rejected(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        approval = next(x for x in values if x['kind'] == 'pack_approval')
        self.invalid(dict(approval, approver_ref=approval['author_ref']))
        assessment = next(x for x in values if x['kind'] == 'requirement_assessment')
        self.invalid(dict(assessment, status='satisfied'))

    def test_clock_values_use_the_same_strict_utc_format(self):
        for value in ('2026-10-29T00:00Z', '2026-10-29', '2026-02-30T00:00:00Z'):
            with self.assertRaises(contracts.ContractError):
                contracts.timestamp(value)

    def rebind(self, values):
        index = {}
        for value in values:
            kind = value['kind']
            name = value.get('id', value.get('pack_id', value.get('event_id')))
            version = str(value.get('revision', value.get('version', '1'))) if kind == 'project_profile' else value.get('version', '1')
            index[(kind, name, version)] = value
        def visit(value):
            if isinstance(value, dict):
                if set(value) == {'kind', 'id', 'version', 'digest'}:
                    target = index.get((value['kind'], value['id'], value['version']))
                    if target is not None:
                        value['digest'] = contracts.digest(target)
                else:
                    for child in value.values():
                        visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)
        for value in values:
            visit(value)

    def test_batch_approval_cannot_bind_another_profile_digest(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        next(x for x in values if x['kind'] == 'profile_approval')['profile_digest'] = 'f' * 64
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values)

    def test_batch_profile_parent_is_checked(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        values.append(dict(self.profile, revision=2, parent_digest='f' * 64))
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values)

    def test_batch_applicability_must_belong_to_the_assessed_requirement(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        other = copy.deepcopy(next(x for x in values if x['kind'] == 'requirement_spec'))
        other['id'] = 'REQ-OTHER'
        values.append(other)
        app = next(x for x in values if x['kind'] == 'applicability_decision')
        app['requirement_ref'] = dict(kind='requirement_spec', id=other['id'], version='1', digest=contracts.digest(other))
        self.rebind(values)
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values)

    def test_batch_review_must_bind_the_evaluation_subject(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        review = next(x for x in values if x['kind'] == 'review_decision')
        review['subject_digest'] = 'f' * 64
        assessment = next(x for x in values if x['kind'] == 'requirement_assessment')
        assessment['review_refs'] = [dict(kind='review_decision', id=review['id'], version='1', digest=contracts.digest(review))]
        self.rebind(values)
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values)

    def test_scoped_legacy_descriptor_resolves_without_granting_approval(self):
        values = json.loads((FIXTURES / 'contract-set.example.json').read_text())
        lock = next(x for x in values if x['kind'] == 'project_pack_lock')
        reference = dict(kind='policy_bundle', id='LEGACY', version='1', digest='c' * 64)
        lock['policy_bundle_refs'] = [reference]
        evaluation = next(x for x in values if x['kind'] == 'project_evaluation')
        evaluation['lock_digest'] = contracts.digest(lock)
        evaluation['subject_digest'] = contracts.evaluation_subject(evaluation)
        self.rebind(values)
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values)
        descriptor = dict(reference, tenant_id='t', project_id='p')
        contracts.validate_set(values, external_refs=[descriptor])
        with self.assertRaises(contracts.ContractError):
            contracts.validate_set(values, external_refs=[dict(descriptor, project_id='other')])


if __name__ == '__main__':
    unittest.main()
