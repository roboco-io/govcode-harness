import copy
import json
from pathlib import Path
import unittest
import tempfile

from govcode_harness import project_contracts as c
from tests.rule_pack_fixtures import Authority,NOW,END,reference

from govcode_harness import applicability as app

FIXTURE = Path(__file__).parent / 'fixtures/project-compliance/profile.example.json'


class ExpressionTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads(FIXTURE.read_text())

    def expression(self, name='public_web', value=False, value_type='boolean'):
        return dict(op='eq', fact=name, value=dict(value_type=value_type, value=value))

    def evaluate(self, expression):
        return app.evaluate_expression(expression, self.profile)

    def test_known_false_is_a_known_value(self):
        result = self.evaluate(self.expression())
        self.assertEqual('true', result['truth'])
        self.assertEqual([], result['pending_facts'])
        self.assertEqual('false', self.evaluate(self.expression(value=True))['truth'])

    def test_missing_unknown_and_na_do_not_coerce_to_false(self):
        for name in ('procurement_type', 'not_supplied', 'mobile_app'):
            result = self.evaluate(self.expression(name))
            self.assertEqual('unknown', result['truth'])
            self.assertEqual([name], result['pending_facts'])

    def test_not_unknown_stays_unknown(self):
        result = self.evaluate(dict(op='not', arg=self.expression('procurement_type')))
        self.assertEqual('unknown', result['truth'])

    def test_all_any_use_three_valued_logic_without_losing_pending_facts(self):
        true, false = self.expression(), self.expression(value=True)
        unknown = self.expression('procurement_type')
        for op, args, expected in [('all',[true,unknown],'unknown'),('all',[false,unknown],'false'),
                                   ('any',[true,unknown],'true'),('any',[false,unknown],'unknown')]:
            result = self.evaluate(dict(op=op,args=args))
            self.assertEqual(expected, result['truth'])
            self.assertEqual(['procurement_type'], result['pending_facts'])

    def test_in_is_typed_and_exact(self):
        expression = dict(op='in', fact='public_web', values=[dict(value_type='boolean',value=False)])
        self.assertEqual('true', self.evaluate(expression)['truth'])
        expression['values'] = [dict(value_type='integer',value=0)]
        with self.assertRaises(app.ApplicabilityError):
            self.evaluate(expression)

    def test_boolean_false_is_not_integer_zero(self):
        with self.assertRaises(app.ApplicabilityError):
            self.evaluate(self.expression(value=0,value_type='integer'))

    def test_heterogeneous_in_rejected_even_when_the_fact_is_unknown(self):
        expression = dict(op='in', fact='not_supplied', values=[dict(value_type='boolean',value=True),dict(value_type='string',value='true')])
        with self.assertRaises(app.ApplicabilityError):
            self.evaluate(expression)

    def test_invalid_operators_and_hidden_commands_are_not_executed(self):
        for expression in [dict(op='eval',code='raise Exception()'),
                           dict(self.expression(),command='arbitrary'),
                           dict(op='any',args=[self.expression(),dict(op='eval',code='pass')])]:
            with self.assertRaises(app.ApplicabilityError):
                self.evaluate(expression)

    def test_expression_depth_and_empty_conditions_rejected(self):
        expr = self.expression()
        for _ in range(17):
            expr = dict(op='not',arg=expr)
        for expression in [expr, dict(op='all',args=[])]:
            with self.assertRaises(app.ApplicabilityError):
                self.evaluate(expression)

    def test_evaluation_does_not_modify_profile_or_return_fact_values(self):
        before = copy.deepcopy(self.profile)
        result = self.evaluate(self.expression('procurement_type'))
        self.assertEqual(before, self.profile)
        self.assertNotIn('facts', result)
        self.assertNotIn('value', result)


class AuthorizedApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir='/private/tmp');self.addCleanup(self.tmp.cleanup)
        self.a=Authority(Path(self.tmp.name))

    def lock(self, expression=None):
        if expression is not None:
            self.a.requirements[0]['applicability_expr']=expression
        return self.a.lock([self.a.publish()])

    def assess(self, lock, **options):
        args=dict(revocations=self.a.feed,expected_revocation_digest=c.digest(self.a.feed),reviews=[])
        args.update(options)
        return app.assess(lock,self.a.profiles,self.a.trust,NOW,**args)

    def review(self, lock, decision='not_applicable', actor='bob', **changes):
        req=reference(self.a.requirements[0])
        fields=dict(lock_digest=c.digest(lock),profile_digest=c.digest(self.a.profile),requirement_ref=req,
                    subject_digest=app.review_subject(c.digest(lock),c.digest(self.a.profile),req,'t','p'),
                    decision=decision,reason_ref='APPLICABILITY-REVIEW',not_before=NOW,expires_at=END)
        fields.update(changes)
        return self.a.signed('applicability_review',actor,**fields)

    def test_verified_example_true_is_applicable_but_not_fulfillment(self):
        report=self.assess(self.lock())
        self.assertEqual(dict(total=1,applicable=1,not_applicable=0,pending=0),report['counts'])
        self.assertEqual('applicability_resolved',report['outcome'])
        self.assertFalse(report['requirements_evaluated'])
        self.assertFalse(report['operational_approval'])

    def test_false_needs_independent_exclusion_review(self):
        lock=self.lock(dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=True)))
        report=self.assess(lock)
        self.assertEqual(1,report['counts']['pending'])
        approved=self.assess(lock,reviews=[self.review(lock)])
        self.assertEqual(1,approved['counts']['not_applicable'])
        self.assertEqual('bob',approved['decisions'][0]['reviewer_ref'])

    def test_unknown_not_unknown_and_missing_remain_review_required(self):
        lock=self.lock(dict(op='not',arg=dict(op='eq',fact='procurement_type',value=dict(value_type='string',value='fixed'))))
        report=self.assess(lock)
        self.assertEqual('review_required',report['outcome'])
        self.assertEqual(1,report['counts']['pending'])
        self.assertTrue(any(x['fact_ref']=='procurement_type' for x in report['next_actions']))

    def test_unknown_branch_is_not_hidden_by_known_true_or_false(self):
        lock=self.lock(dict(op='any',args=[dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=False)),
                                           dict(op='eq',fact='not_supplied',value=dict(value_type='boolean',value=True))]))
        report=self.assess(lock)
        self.assertEqual('true',report['conditions'][0]['truth'])
        self.assertEqual(1,report['counts']['pending'])

    def test_manual_review_cannot_resolve_unknown_without_new_profile(self):
        lock=self.lock(dict(op='eq',fact='procurement_type',value=dict(value_type='string',value='fixed')))
        with self.assertRaises(app.ApplicabilityError):
            self.assess(lock,reviews=[self.review(lock)])

    def test_same_author_with_another_key_cannot_approve_exclusion(self):
        lock=self.lock(dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=True)))
        with self.assertRaises(app.ApplicabilityError):
            self.assess(lock,reviews=[self.review(lock,actor='alice2')])

    def test_expired_revoked_changed_and_duplicate_reviews_rejected(self):
        lock=self.lock(dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=True)))
        review=self.review(lock)
        for reviews in ([self.review(lock,expires_at=NOW)],[self.review(lock,profile_digest='f'*64)],[review,review]):
            with self.assertRaises(app.ApplicabilityError):self.assess(lock,reviews=reviews)
        self.a.feed=self.a.issue_feed(review_digests=[c.digest(review)])
        with self.assertRaises(app.ApplicabilityError):self.assess(lock,reviews=[review])

    def test_signed_review_cannot_contradict_a_known_condition(self):
        lock=self.lock()
        with self.assertRaises(app.ApplicabilityError):self.assess(lock,reviews=[self.review(lock)])

    def test_non_example_requirement_needs_an_applicability_review(self):
        req=self.a.requirements[0]
        req.update(source_category='statute',basis_kind='statutory_obligation',normativity='mandatory')
        req['source_ref']['category']='statute'
        self.a.manifest['source_refs'][0]['category']='statute'
        lock=self.lock()
        self.assertEqual(1,self.assess(lock)['counts']['pending'])
        self.assertEqual(1,self.assess(lock,reviews=[self.review(lock,decision='applicable')])['counts']['applicable'])

    def test_old_lock_and_review_do_not_apply_to_a_new_profile_revision(self):
        expression=dict(op='eq',fact='public_web',value=dict(value_type='boolean',value=True))
        release=self.a.publish()
        lock=self.a.lock([release]);review=self.review(lock,decision='applicable')
        profile=copy.deepcopy(self.a.profile);profile.update(revision=2,parent_digest=c.digest(self.a.profile))
        self.a.approve_profile(profile)
        with self.assertRaises(app.ApplicabilityError):self.assess(lock,reviews=[review])
        new_lock=self.a.lock([release],sequence=2)
        with self.assertRaises(app.ApplicabilityError):self.assess(new_lock,reviews=[review])

    def test_retired_profile_and_forged_lock_are_errors_not_exclusions(self):
        lock=self.lock()
        bad=copy.deepcopy(lock);bad['payload']['lock']['sequence']=100
        with self.assertRaises(app.ApplicabilityError):self.assess(bad)
        target=dict(profile_id=self.a.profile['id'],revision=1,profile_digest=c.digest(self.a.profile),expected_revision=1,
                    action='retire',reason_ref='PROFILE-RETIRED')
        self.a.profiles.apply(self.a.signed('profile_action','ops',**target),NOW)
        with self.assertRaises(app.ApplicabilityError):self.assess(lock)

    def test_shared_requirement_has_one_denominator_entry(self):
        first=self.a.publish()
        manifest,reqs=self.a.make_pack('PACK-OTHER')
        second=self.a.publish(manifest,reqs)
        self.assertEqual(1,self.assess(self.a.lock([first,second]))['counts']['total'])

    def test_a_review_event_id_cannot_identify_two_different_approvals(self):
        self.a.requirements[0]['applicability_expr']['value']['value']=True
        other=copy.deepcopy(self.a.requirements[0]);other['id']='REQ-SECOND'
        self.a.requirements.append(other)
        lock=self.a.lock([self.a.publish()])
        one=self.review(lock)
        ref=reference(other)
        two=self.review(lock,requirement_ref=ref,
            subject_digest=app.review_subject(c.digest(lock),c.digest(self.a.profile),ref,'t','p'),event_id=one['payload']['event_id'])
        with self.assertRaises(app.ApplicabilityError):self.assess(lock,reviews=[one,two])

    def test_report_counts_cannot_hide_a_pending_requirement(self):
        report=self.assess(self.lock(dict(op='eq',fact='procurement_type',value=dict(value_type='string',value='fixed'))))
        report['counts'].update(pending=0,applicable=1)
        report['outcome']='applicability_resolved'
        with self.assertRaises(c.ContractError):c.validate(report)

    def test_report_conditions_must_match_the_decision_references(self):
        report=self.assess(self.lock())
        report['conditions'][0]['requirement_ref']['id']='UNRELATED'
        with self.assertRaises(c.ContractError):c.validate(report)


if __name__ == '__main__':
    unittest.main()
