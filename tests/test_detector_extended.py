"""R2 bounded helper and exception regression cases."""
import unittest
from govcode_harness.detector import analyze

class ExtendedDetectorTests(unittest.TestCase):
    def check(self, source, finding=False, review=False):
        result = analyze(source, 'PRIVATE_PATH')
        self.assertTrue(result['parsed'])
        self.assertEqual(bool(result['findings']), finding, result)
        self.assertEqual(bool(result['issues']), review, result)
        return result

    def test_private_constant(self):
        self.check('def _redact(data):\n return "fixed"\ndef handle(body, logger):\n logger.info(_redact(body))')

    def test_private_argument_and_return(self):
        self.check('def _id(value):\n return value\ndef handle(body, logger):\n logger.info(_id(body))', True)

    def test_private_keyword(self):
        self.check('def _id(value):\n return value\ndef handle(body, logger):\n logger.info(_id(value=body))', True)

    def test_private_sink_uses_callers(self):
        self.check('def _emit(value, logger):\n logger.info(value)\ndef handle(logger):\n _emit("fixed", logger)')

    def test_private_parameter_name_cannot_sanitize(self):
        self.check('def _emit(request_id, logger):\n logger.info(request_id)\ndef handle(body, logger):\n _emit(body, logger)', True)

    def test_public_parameter_conservative(self):
        self.check('def emit(value, logger):\n logger.info(value)', True)

    def test_recursive_private_review(self):
        self.check('def _a(value):\n return _a(value)\ndef handle(body, logger):\n logger.info(_a(body))', True, True)

    def test_private_escape_review(self):
        self.check('def _a(value):\n return value\nexport = _a\ndef handle(logger):\n logger.info(_a("fixed"))', review=True)

    def test_exception_body(self):
        self.check('def handle(body, logger):\n try:\n  raise ValueError("fixed")\n except ValueError:\n  logger.info(body)', True)

    def test_exception_value(self):
        self.check('def handle(body, logger):\n try:\n  raise ValueError(body)\n except ValueError as error:\n  logger.error(error)', True, True)

    def test_implicit_exception_finding(self):
        self.check('def handle(body, logger):\n try:\n  raise ValueError(body)\n except ValueError:\n  logger.exception("fixed")', True, True)

    def test_exception_false_suppresses_traceback(self):
        self.check('def handle(body, logger):\n try:\n  raise ValueError(body)\n except ValueError:\n  logger.error("fixed", exc_info=False)')

    def test_branch_join(self):
        self.check('def handle(body, status, logger):\n value = body\n if status:\n  value = "fixed"\n logger.info(value)', True)

    def test_uncalled_mutual_recursion_review(self):
        self.check('def _a(value):\n return _b(value)\ndef _b(value):\n return _a(value)\npass', review=True)

    def test_decorated_private_review(self):
        result = analyze('@wrapper\ndef _a(value):\n return value\ndef handle(logger):\n logger.info(_a("fixed"))', '')
        self.assertTrue(result['issues'])

    def test_private_keyword_logger_role(self):
        self.check('def _emit(value, sink):\n sink.info(value)\ndef handle(logger):\n _emit(value="fixed", sink=logger)')

    def test_helper_limit_review(self):
        source = '\n'.join('def _h%d(value):\n return _h%d(value)' % (i, i+1) for i in range(18))
        source += '\ndef _h18(value):\n return value\ndef handle(body, logger):\n logger.info(_h0(body))'
        self.check(source, True, True)

    def test_rebound_private_review(self):
        result = analyze('def _a(value):\n return "fixed"\ndef handle(body, logger):\n _a = external\n logger.info(_a(body))', '')
        self.assertTrue(result['issues'])

    def test_explicit_raise_constant_handler_clean(self):
        self.check('def handle(payload, logger):\n try:\n  raise ValueError(payload)\n except ValueError:\n  logger.info("fixed event")')

    def test_explicit_raise_metadata_handler_clean(self):
        self.check('def handle(payload, request_id, logger):\n try:\n  raise ValueError(payload)\n except ValueError as caught:\n  logger.warning("event %s", request_id)')

    def test_implicit_only_try_still_review(self):
        self.check('def handle(logger):\n try:\n  logger.info("fixed")\n except Exception:\n  pass', review=True)
