import json
from email.message import Message
from io import BytesIO
import unittest
from govcode_harness.sample_api import ApiInputError, ComplaintHandler, process_payload

class Capture:
    def __init__(self): self.calls = []
    def info(self, *args, **kwargs): self.calls.append((args, kwargs))
    def record_event(self, *args, **kwargs): self.calls.append((args, kwargs))

class ApiTests(unittest.TestCase):
    def test_fixed_payload_records_minimal_log_and_audit(self):
        logger, audit = Capture(), Capture()
        result = process_payload(json.dumps({'complaint_text':'PRIVATE_SENTINEL'}).encode(), logger, audit)
        self.assertEqual(result['status'], 'received')
        self.assertEqual(len(result['request_id']), 32)
        self.assertNotIn('PRIVATE_SENTINEL', repr(logger.calls))
        self.assertNotIn('PRIVATE_SENTINEL', repr(audit.calls))
        self.assertEqual(len(audit.calls), 1)

    def test_invalid_payload_does_not_echo_body(self):
        for raw in [b'not json PRIVATE_SENTINEL', b'[]', b'null', b'\xff', b'x' * 65537]:
            with self.subTest(size=len(raw)):
                with self.assertRaises(ApiInputError) as result:
                    process_payload(raw, Capture(), Capture())
                self.assertNotIn('PRIVATE_SENTINEL', str(result.exception))

    def test_content_length_is_bounded_ascii_decimal(self):
        for length in ['²', '1' * 5000, '-1', '9999999999']:
            with self.subTest(length_size=len(length)):
                handler = ComplaintHandler.__new__(ComplaintHandler)
                handler.path = '/complaints'
                handler.headers = Message()
                handler.headers['Content-Length'] = length
                handler.headers['Content-Type'] = 'application/json'
                handler.rfile = BytesIO(b'{}')
                replies = []
                handler.reply = lambda status, body: replies.append((status, body))
                handler.do_POST()
                self.assertIn(replies[0][0], [400, 413])

if __name__ == '__main__': unittest.main()
