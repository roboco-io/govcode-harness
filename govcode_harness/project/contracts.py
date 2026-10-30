"""Closed, local Draft-07 contracts; validation never grants approval or runs a pack."""
import datetime as dt
import functools
import hashlib
import json
import re
from pathlib import Path

from .. import security

SCHEMA_ROOT = Path(__file__).parents[1] / 'contracts'
FAMILIES = ('project-common', 'project-profile', 'rule-pack', 'project-evaluation')
REF_FIELDS = {'kind', 'id', 'version', 'digest'}


class ContractError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def digest(value):
    try:
        return hashlib.sha256(security.canonical(value)).hexdigest()
    except security.SecurityError as error:
        raise ContractError(error.code) from None


def timestamp(value):
    try:
        if not isinstance(value, str) or re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z', value) is None:
            raise ValueError()
        result = dt.datetime.fromisoformat(value[:-1] + '+00:00')
        if result.utcoffset() != dt.timedelta(0):
            raise ValueError()
        return result
    except (TypeError, ValueError, OverflowError):
        raise ContractError('TIME_INVALID') from None


@functools.lru_cache(maxsize=1)
def _validators():
    from jsonschema import Draft7Validator, FormatChecker
    from referencing import Registry, Resource
    schemas = [security.read_json(SCHEMA_ROOT / (name + '.schema.json')) for name in FAMILIES]
    registry = Registry().with_resources((s['$id'], Resource.from_contents(s)) for s in schemas)
    checker = FormatChecker(formats=[])

    @checker.checks('date-time')
    def utc_date(value):
        try:
            timestamp(value)
            return True
        except ContractError:
            return False

    result = {}
    for schema in schemas:
        Draft7Validator.check_schema(schema)
        for kind in schema['definitions']:
            if schema is schemas[0]:
                continue
            result[kind] = Draft7Validator(
                {'$ref': schema['$id'] + '#/definitions/' + kind},
                registry=registry, format_checker=checker,
            )
    return result


def _require(condition, code='CONTRACT_INVALID'):
    if not condition:
        raise ContractError(code)


def _unique(values, code):
    _require(len(values) == len(set(values)), code)


def _expression_limit(expression):
    stack = [(expression, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        _require(depth <= 16 and nodes <= 256, 'EXPRESSION_LIMIT')
        if isinstance(item, dict):
            if isinstance(item.get('args'), list):
                stack.extend((arg, depth + 1) for arg in item['args'])
            if 'arg' in item:
                stack.append((item['arg'], depth + 1))


@functools.lru_cache(maxsize=1)
def _expression_validator():
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    common = security.read_json(SCHEMA_ROOT / 'project-common.schema.json')
    registry = Registry().with_resource(common['$id'], Resource.from_contents(common))
    return Draft7Validator({'$ref': common['$id'] + '#/definitions/expression'}, registry=registry)


def validate_expression(expression):
    try:
        result = json.loads(security.canonical(expression))
        _expression_limit(result)
        _require(_expression_validator().is_valid(result), 'EXPRESSION_INVALID')
        return result
    except ContractError:
        raise
    except security.SecurityError as error:
        raise ContractError(error.code) from None
    except Exception:
        raise ContractError('EXPRESSION_INVALID') from None


def _sources(value):
    sources = value.get('source_refs', [])
    _unique([s['id'] for s in sources], 'SOURCE_ID_DUPLICATE')
    for source in sources + ([value['source_ref']] if 'source_ref' in value else []):
        if source['verification'] == 'confirmed':
            _require(source['digest'] is not None, 'SOURCE_DIGEST_REQUIRED')
    return {s['id']: s for s in sources}


def _ref_kind(value, field, kind):
    _require(value[field]['kind'] == kind, 'REFERENCE_KIND_INVALID')


def evaluation_subject(value):
    """The approval subject excludes approvals, their signatures and the final result."""
    fields = ('schema_version', 'context', 'tenant_id', 'project_id', 'operational_approval',
              'commit_sha', 'profile_digest', 'lock_digest', 'artifact_manifest_digest', 'tool_digest')
    try:
        return digest({key: value[key] for key in fields})
    except KeyError:
        raise ContractError('SUBJECT_INPUT_MISSING') from None


def _semantics(value):
    kind = value['kind']
    sources = _sources(value)
    if 'not_before' in value:
        _require(timestamp(value['not_before']) < timestamp(value['expires_at']), 'TIME_WINDOW_INVALID')
        if 'created_at' in value:
            _require(timestamp(value['created_at']) < timestamp(value['expires_at']), 'TIME_WINDOW_INVALID')
    if kind == 'project_profile':
        _require((value['revision'] == 1) == (value['parent_digest'] is None), 'PROFILE_PARENT_INVALID')
        for fact in value['facts'].values():
            if fact['state'] != 'unknown':
                source = sources.get(fact['source_ref'])
                _require(source is not None and source['verification'] == 'confirmed', 'FACT_SOURCE_UNVERIFIED')
    elif kind == 'profile_action' and value['action'] == 'revise':
        profile = validate(value['profile'])
        _require((profile['tenant_id'], profile['project_id']) == (value['tenant_id'], value['project_id']), 'SCOPE_MISMATCH')
        _require(profile['revision'] == value['expected_revision'] + 1, 'PROFILE_REVISION_INVALID')
    elif kind == 'rule_pack_manifest':
        for field, expected in [('requirement_refs', 'requirement_spec'), ('dependencies', 'rule_pack_manifest')]:
            _unique([(r['kind'], r['id'], r['version']) for r in value[field]], 'REFERENCE_DUPLICATE')
            _require(all(r['kind'] == expected for r in value[field]), 'REFERENCE_KIND_INVALID')
        for field in ('check_specs', 'task_templates'):
            _unique([x['id'] for x in value[field]], 'ITEM_ID_DUPLICATE')
    elif kind == 'requirement_spec':
        source = value['source_ref']
        _require(source['category'] == value['source_category'] and source['verification'] == value['source_verification'], 'SOURCE_CLASSIFICATION_MISMATCH')
        if value['basis_kind'] == 'statutory_obligation':
            _require(value['source_category'] in ('statute', 'administrative_rule') and value['source_verification'] == 'confirmed', 'STATUTORY_SOURCE_UNVERIFIED')
    elif kind == 'pack_approval':
        _ref_kind(value, 'pack_ref', 'rule_pack_manifest')
        _require(value['manifest_digest'] == value['pack_ref']['digest'], 'REFERENCE_DIGEST_MISMATCH')
        _require(value['author_ref'] != value['approver_ref'], 'SELF_APPROVAL')
    elif kind == 'project_pack_lock':
        _ref_kind(value, 'profile_ref', 'project_profile')
        _require(value['profile_digest'] == value['profile_ref']['digest'], 'REFERENCE_DIGEST_MISMATCH')
        _require(all(r['kind'] == 'rule_pack_manifest' for r in value['pack_refs']), 'REFERENCE_KIND_INVALID')
        _unique([(r['id'], r['version']) for r in value['pack_refs']], 'REFERENCE_DUPLICATE')
        _require(all(r['kind'] == 'policy_bundle' for r in value['policy_bundle_refs']), 'REFERENCE_KIND_INVALID')
    elif kind == 'applicability_decision':
        _ref_kind(value, 'requirement_ref', 'requirement_spec')
        if value['result'] == 'not_applicable':
            _require(value['reviewer_ref'] is not None and value['review_ref'] is not None, 'EXCLUSION_REVIEW_REQUIRED')
    elif kind in ('review_decision', 'work_item', 'requirement_assessment'):
        _ref_kind(value, 'requirement_ref', 'requirement_spec')
        if kind == 'requirement_assessment':
            _ref_kind(value, 'applicability_ref', 'applicability_decision')
            _require(all(r['kind'] == 'review_decision' for r in value['review_refs']), 'REFERENCE_KIND_INVALID')
            _unique([r['check_id'] for r in value['check_results']], 'ITEM_ID_DUPLICATE')
            if value['status'] == 'satisfied':
                _require(bool(value['check_results']) and all(x['status'] == 'pass' for x in value['check_results']), 'ASSESSMENT_INCOMPLETE')
                _require(not value['manual_review_required'] or bool(value['review_refs']), 'ASSESSMENT_REVIEW_REQUIRED')
    elif kind == 'project_evaluation':
        _require(value['subject_digest'] == evaluation_subject(value), 'SUBJECT_DIGEST_MISMATCH')
        _require(all(r['kind'] == 'requirement_assessment' for r in value['assessments']), 'REFERENCE_KIND_INVALID')
        if value['parent_ref'] is not None:
            _ref_kind(value, 'parent_ref', 'project_evaluation')
    elif kind == 'project_stage_receipt':
        _ref_kind(value, 'evaluation_ref', 'project_evaluation')
    elif kind == 'project_applicability_report':
        _ref_kind(value, 'profile_ref', 'project_profile')
        counts = {key: 0 for key in ('total','applicable','not_applicable','pending')}
        references = set()
        for row in value['decisions']:
            _require((row['tenant_id'],row['project_id']) == (value['tenant_id'],value['project_id']), 'SCOPE_MISMATCH')
            _require(row['profile_digest'] == value['profile_ref']['digest'], 'PROFILE_DIGEST_MISMATCH')
            key = digest(row['requirement_ref'])
            _require(key not in references, 'REQUIREMENT_DUPLICATE')
            references.add(key)
            counts['total'] += 1
            counts[row['result']] += 1
        _require(counts == value['counts'], 'APPLICABILITY_COUNTS_INVALID')
        _require(value['outcome'] == ('review_required' if counts['pending'] else 'applicability_resolved'), 'APPLICABILITY_OUTCOME_INVALID')
        _require(len(value['conditions']) == len(references) and {digest(r['requirement_ref']) for r in value['conditions']} == references, 'REQUIREMENT_REFERENCE_MISMATCH')
        _require(all(digest(r['requirement_ref']) in references for r in value['next_actions']), 'REQUIREMENT_REFERENCE_MISMATCH')


def validate(value):
    """Return detached validated data. Shape/relations are not signature or legal checks."""
    try:
        result = json.loads(security.canonical(value))
        _require(isinstance(result, dict) and result.get('kind') in _validators())
        if 'applicability_expr' in result:
            _expression_limit(result['applicability_expr'])
        _require(_validators()[result['kind']].is_valid(result))
        _semantics(result)
        return result
    except ContractError:
        raise
    except security.SecurityError as error:
        raise ContractError(error.code) from None
    except Exception:
        raise ContractError('CONTRACT_INVALID') from None


def load(path):
    try:
        return validate(security.read_json(path))
    except security.SecurityError as error:
        raise ContractError(error.code) from None


def _identity(value):
    kind = value['kind']
    if kind == 'project_profile':
        return kind, value['id'], str(value['revision'])
    if kind == 'rule_pack_manifest':
        return kind, value['pack_id'], value['version']
    if 'event_id' in value:
        return kind, value['event_id'], '1'
    return kind, value['id'], value['version']


def _references(value):
    if isinstance(value, dict):
        if set(value) == REF_FIELDS:
            yield value
        else:
            for child in value.values():
                yield from _references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _references(child)


def validate_set(values, *, external_refs=()):
    """Resolve references, not approvals. Legacy descriptors must be separately verified.

    Opaque source/reason IDs and all cryptographic authority need later checks.
    external_refs contains only scoped descriptors of legacy source/policy data.
    """
    try:
        security.canonical(values)
        _require(type(values) is list and 0 < len(values) <= 1000)
        result = [validate(x) for x in values]
        scope = (result[0]['tenant_id'], result[0]['project_id'])
        index = {}
        for value in result:
            _require((value['tenant_id'], value['project_id']) == scope, 'SCOPE_MISMATCH')
            key = _identity(value)
            _require(key not in index, 'ENTITY_DUPLICATE')
            index[key] = value
        hashes = {key: digest(value) for key, value in index.items()}
        _require(isinstance(external_refs, (list, tuple)) and len(external_refs) <= 256, 'EXTERNAL_REFERENCE_INVALID')
        security.canonical(list(external_refs))
        for reference in external_refs:
            _require(type(reference) is dict and set(reference) == REF_FIELDS | {'tenant_id', 'project_id'}, 'EXTERNAL_REFERENCE_INVALID')
            _require((reference['tenant_id'], reference['project_id']) == scope, 'SCOPE_MISMATCH')
            _require(reference['kind'] in ('policy_bundle', 'source'), 'EXTERNAL_REFERENCE_INVALID')
            security.identifier(reference['id'])
            security.identifier(reference['version'])
            _require(type(reference['digest']) is str and re.fullmatch(r'[a-f0-9]{64}', reference['digest']) is not None, 'EXTERNAL_REFERENCE_INVALID')
            key = reference['kind'], reference['id'], reference['version']
            _require(key not in hashes, 'ENTITY_DUPLICATE')
            hashes[key] = reference['digest']
        for value in result:
            for reference in _references(value):
                key = reference['kind'], reference['id'], reference['version']
                _require(key in hashes, 'REFERENCE_MISSING')
                _require(reference['digest'] == hashes[key], 'REFERENCE_DIGEST_MISMATCH')

        def target(reference):
            return index[(reference['kind'], reference['id'], reference['version'])]

        for value in result:
            if value['kind'] == 'project_profile' and value['revision'] > 1:
                parent = ('project_profile', value['id'], str(value['revision'] - 1))
                _require(parent in hashes and hashes[parent] == value['parent_digest'], 'PROFILE_PARENT_MISMATCH')
            if value['kind'] in ('profile_action', 'profile_approval'):
                if value.get('action') == 'revise':
                    key = _identity(value['profile'])
                    expected = digest(value['profile'])
                else:
                    key = ('project_profile', value['profile_id'], str(value['revision']))
                    expected = value['profile_digest']
                _require(key in hashes and hashes[key] == expected, 'PROFILE_DIGEST_MISMATCH')
            if value['kind'] == 'rule_pack_manifest':
                sources = {(s['id'], s['version']): s for s in value['source_refs']}
                checks = {x['id'] for x in value['check_specs']}
                for reference in value['requirement_refs']:
                    requirement = target(reference)
                    source = requirement['source_ref']
                    _require(sources.get((source['id'], source['version'])) == source, 'SOURCE_REFERENCE_MISMATCH')
                    _require(set(requirement['check_refs']) <= checks, 'CHECK_REFERENCE_MISSING')
            if value['kind'] == 'requirement_assessment':
                requirement = target(value['requirement_ref'])
                applicability = target(value['applicability_ref'])
                _require(applicability['requirement_ref'] == value['requirement_ref'], 'REQUIREMENT_REFERENCE_MISMATCH')
                _require(value['manual_review_required'] == requirement['review_required'], 'REVIEW_REQUIREMENT_MISMATCH')
                for ref in value['review_refs']:
                    _require(target(ref)['requirement_ref'] == value['requirement_ref'], 'REQUIREMENT_REFERENCE_MISMATCH')
                if value['status'] == 'satisfied':
                    _require(applicability['result'] == 'applicable', 'APPLICABILITY_UNCONFIRMED')
                    for ref in value['review_refs']:
                        _require(target(ref)['decision'] == 'approved', 'REVIEW_UNAPPROVED')
            if value['kind'] == 'project_evaluation':
                profiles = [p for k, p in index.items() if k[0] == 'project_profile' and digest(p) == value['profile_digest']]
                locks = [p for k, p in index.items() if k[0] == 'project_pack_lock' and digest(p) == value['lock_digest']]
                _require(len(profiles) == len(locks) == 1, 'EVALUATION_INPUT_MISSING')
                _require(locks[0]['profile_digest'] == value['profile_digest'], 'PROFILE_DIGEST_MISMATCH')
                reviews = {}
                for ref in value['assessments']:
                    for review_ref in target(ref)['review_refs']:
                        review = target(review_ref)
                        _require(review['subject_digest'] == value['subject_digest'], 'REVIEW_SUBJECT_MISMATCH')
                        reviews[(review_ref['id'], review_ref['version'])] = review_ref
                _require(value['review_set_digest'] == digest([reviews[k] for k in sorted(reviews)]), 'REVIEW_SET_DIGEST_MISMATCH')
        return result
    except ContractError:
        raise
    except security.SecurityError as error:
        raise ContractError(error.code) from None
    except Exception:
        raise ContractError('CONTRACT_INVALID') from None
