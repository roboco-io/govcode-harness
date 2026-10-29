"""Bounded-source propagation checks; no claim of whole-program analysis."""
from pathlib import Path
import textwrap
import unittest

from govcode_harness.detector import analyze


def sample(statement):
    return 'def submit(request_body, request_id, logger, audit):\n' + textwrap.indent(statement, '    ')


POSITIVE = [
    'logger.info(request_body)',
    'logger.debug("body=%s", request_body)',
    'logger.warning("%r", request_body)',
    'logger.error(f"body={request_body}")',
    'logger.exception("%s" % request_body)',
    'logger.critical("{}".format(request_body))',
    'logger.log(20, request_body)',
    'alias = request_body\nlogger.info(alias)',
    'alias = request_body\nsecond = alias\nlogger.info(second)',
    'logger.info(request_body["phone"])',
    'logger.info(request_body.get("phone"))',
    'logger.info(str(request_body))',
    'logger.info(repr(request_body))',
    'logger.info({"wrapped": request_body})',
    'logger.info([request_body])',
    'logger.info((request_body,))',
    'logger.info("prefix" + str(request_body))',
    'logger.info("event", extra={"details": request_body})',
    'if request_id:\n    value = request_body\nelse:\n    value = "ok"\nlogger.info(value)',
    'value: dict = request_body\nlogger.info(value)',
    'value = "ok"\nvalue += str(request_body)\nlogger.info(value)',
    'print(request_body)',
    'logger.info({"phone": "SYNTHETIC"})',
    'logger.info(request_body.phone)',
    'logger.info(dict(phone="SYNTHETIC"))',
]

NEGATIVE = [
    'logger.info("received")',
    'logger.info("request=%s", request_id)',
    'logger.info("event", extra={"request_id": request_id})',
    'logger.info("event", extra={"operation": "submit", "result_code": "ok"})',
    'value = "ok"\nlogger.info(value)',
    'value = {"operation": "submit"}\nlogger.info(value)',
    'value = ["received", "ok"]\nlogger.info(value)',
    'value = ("received", "ok")\nlogger.info(value)',
    'value = request_body\nvalue = "redacted"\nlogger.info(value)',
    'logger.debug("%s", "ok")',
    'logger.warning("%s", 10)',
    'logger.error("%s", None)',
    'logger.critical("%s", True)',
    'logger.log(20, "event")',
    'logger.info(f"request={request_id}")',
    'logger.info("request={}".format(request_id))',
    'logger.info("request=%s" % request_id)',
    'audit.record_event("received", request_id=request_id)',
    'return {"request_id": request_id, "result_code": "received"}',
    'if request_id:\n    value = "a"\nelse:\n    value = "b"\nlogger.info(value)',
    'value: str = "event"\nlogger.info(value)',
    'pass',
    'logger.info(str(123))',
    'logger.info(" received ".strip())',
]


class DetectorTests(unittest.TestCase):
    def test_unknown_transform_cannot_sanitize(self):
        result = analyze(sample('value = redact(request_body)\nlogger.info(value)'), 'safe.py')
        self.assertTrue(result['findings'])
        self.assertTrue(result['issues'])

    def test_unsupported_constructs_require_review(self):
        statements = [
            'for value in request_body:\n    logger.info(value)',
            'while request_id:\n    break',
            'try:\n    logger.info("event")\nexcept Exception:\n    pass',
            'with request_body:\n    pass',
            'values = [x for x in request_body]',
            'emit = lambda value: logger.info(value)',
            'request_body["phone"] = "synthetic"',
            'logger.info(*request_body)',
            'logger.info("event", **request_body)',
            'def nested():\n    logger.info(request_body)',
        ]
        for statement in statements:
            with self.subTest(statement=statement):
                self.assertTrue(analyze(sample(statement), 'safe.py')['issues'])

    def test_unknown_call_without_tainted_arguments_requires_review(self):
        self.assertTrue(analyze(sample('load_and_log()'), 'safe.py')['issues'])

    def test_tainted_audit_is_not_silently_allowed(self):
        self.assertTrue(analyze(sample('audit.record_event("event", detail=request_body)'), 'safe.py')['issues'])

    def test_rebinding_logger_import_requires_review(self):
        result = analyze('import logging\nlogging = custom\nlogging.info("event")', 'safe.py')
        self.assertTrue(result['issues'])

    def test_unknown_name_cannot_be_clean(self):
        self.assertTrue(analyze(sample('logger.info(missing_name)'), 'safe.py')['issues'])

    def test_imported_logging_aliases(self):
        result = analyze('from logging import info as emit\ndef f(body):\n    emit(body)', 'safe.py')
        self.assertTrue(result['findings'])

    def test_source_parameter_names(self):
        for name in ['body', 'payload', 'request', 'phone', 'email', 'address', 'national_identifier']:
            with self.subTest(name=name):
                self.assertTrue(analyze(f'def f({name}, logger):\n    logger.info({name})', 'safe.py')['findings'])

    def test_unknown_parameter_is_conservatively_tainted(self):
        self.assertTrue(analyze('def wrapper(value, logger):\n    logger.info(value)', 'safe.py')['findings'])

    def test_tainted_receiver_cannot_be_clean(self):
        self.assertTrue(analyze('def api(request_body):\n    request_body.info()', 'safe.py')['issues'])

    def test_arbitrary_imported_receiver_cannot_be_clean(self):
        self.assertTrue(analyze('from custom import service\nservice.info("event")', 'safe.py')['issues'])

    def test_logger_alias_is_supported(self):
        result = analyze(sample('alias = logger\nalias.info(request_body)'), 'safe.py')
        self.assertTrue(result['findings'])
        self.assertEqual(result['issues'], [])

    def test_bare_annotation_preserves_source_taint(self):
        self.assertTrue(analyze(sample('request_body: dict\nlogger.info(request_body)'), 'safe.py')['findings'])

    def test_default_expression_always_inspected(self):
        self.assertTrue(analyze('def f(body=load_private_data()):\n    pass', 'safe.py')['issues'])

    def test_tainted_logger_factory_requires_review(self):
        self.assertTrue(analyze('import logging\ndef f(body):\n    logger = logging.getLogger(str(body))', 'safe.py')['issues'])

    def test_tainted_branch_cannot_be_clean(self):
        source = sample('if request_body:\n    value = "yes"\nelse:\n    value = "no"\nlogger.info(value)')
        self.assertTrue(analyze(source, 'safe.py')['issues'])

    def test_implicit_exception_details_require_review(self):
        for statement in ['logger.exception("failed")', 'logger.error("failed", exc_info=True)']:
            with self.subTest(statement=statement):
                self.assertTrue(analyze(sample(statement), 'safe.py')['issues'])

    def test_logging_factory_and_alias_are_supported(self):
        result = analyze('import logging as logs\nlogger = logs.getLogger(__name__)\nlogger.info("event")', 'safe.py')
        self.assertEqual(result, {'findings': [], 'issues': [], 'parsed': True})

    def test_imported_exception_sink_requires_review(self):
        result = analyze('from logging import exception as emit\nemit("failed")', 'safe.py')
        self.assertTrue(result['issues'])

    def test_module_global_source(self):
        result = analyze('body = request\ndef f(logger):\n    logger.info(body)', 'safe.py')
        self.assertTrue(result['findings'])
        self.assertTrue(result['issues'])

    def test_syntax_error_is_sanitized(self):
        result = analyze('def INVALID_SECRET_SENTINEL(', 'safe.py')
        self.assertFalse(result['parsed'])
        self.assertNotIn('SECRET_SENTINEL', str(result))

    def test_empty_scope_requires_review(self):
        result = analyze('# no implementation', 'safe.py')
        self.assertTrue(result['issues'])

    def test_size_limit(self):
        result = analyze('#' * (256 * 1024 + 1), 'safe.py')
        self.assertFalse(result['parsed'])
        self.assertTrue(result['issues'])

    def test_deep_input_cannot_escape(self):
        result = analyze('x=' + '(' * 2000 + '0' + ')' * 2000, 'safe.py')
        self.assertFalse(result['parsed'])

    def test_output_contains_only_contract_fields(self):
        result = analyze(sample('logger.info(request_body)'), 'PRIVATE_PATH_SENTINEL.py')
        self.assertEqual(set(result), {'findings', 'issues', 'parsed'})
        for finding in result['findings']:
            self.assertEqual(set(finding), {'line', 'category', 'severity', 'data_classes'})
        self.assertNotIn('PRIVATE_PATH_SENTINEL', str(result))

    def test_reproducible_results(self):
        source = sample('logger.info(request_body)\nlogger.debug(request_body)')
        self.assertEqual(analyze(source, 'safe.py'), analyze(source, 'safe.py'))

    def test_authored_before_after(self):
        root = Path(__file__).resolve().parents[1] / 'examples/complaints-api'
        before = analyze((root / 'before.py').read_text(), 'before.py')
        after = analyze((root / 'after.py').read_text(), 'after.py')
        self.assertTrue(before['findings'])
        self.assertEqual(before['issues'], [])
        self.assertEqual(after, {'findings': [], 'issues': [], 'parsed': True})


def case(source, positive):
    def test(self):
        result = analyze(sample(source), 'safe.py')
        self.assertTrue(result['parsed'])
        self.assertEqual(bool(result['findings']), positive)
        self.assertEqual(result['issues'], [])
    return test


for number, statement in enumerate(POSITIVE, 1):
    setattr(DetectorTests, f'test_positive_{number:02}', case(statement, True))
for number, statement in enumerate(NEGATIVE, 1):
    setattr(DetectorTests, f'test_negative_{number:02}', case(statement, False))

if __name__ == '__main__':
    unittest.main()
