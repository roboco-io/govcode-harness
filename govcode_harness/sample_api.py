"""Built-in synthetic API; not an institution's production complaints service."""
import json
import logging
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
import uuid

from .runtime import AFTER_SOURCE, HarnessError

MAX_BODY = 65536

class ApiInputError(Exception):
    def __init__(self, code='INVALID_PAYLOAD', status=400):
        self.code, self.status = code, status
        super().__init__(code)

class AuditCounter:
    """An in-memory demo event counter, not a statutory access-log backend."""
    def __init__(self): self.events = 0
    def record_event(self, event, *, request_id): self.events += 1

def process_payload(raw, logger, audit):
    if len(raw) > MAX_BODY:
        raise ApiInputError('PAYLOAD_TOO_LARGE', 413)
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError):
        raise ApiInputError() from None
    if not isinstance(payload, dict):
        raise ApiInputError()
    # Only the fixed authored constant is compiled, never a file from a repo.
    namespace = {'__builtins__':{}}
    exec(compile(AFTER_SOURCE, '<authored-fixed-api>', 'exec'), namespace)
    return namespace['submit_complaint'](payload, uuid.uuid4().hex, logger, audit)

class ComplaintHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def log_message(self, format, *args):
        pass  # Do not put URL, request line, headers or payload in server logs.
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
    def reply(self, status, value):
        raw = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_POST(self):
        if self.path != '/complaints':
            self.reply(404, {'error':'NOT_FOUND'})
            return
        if self.headers.get('Transfer-Encoding') is not None:
            self.reply(400, {'error':'INVALID_LENGTH'})
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
            self.reply(400, {'error':'INVALID_LENGTH'})
            return
        length = int(lengths[0])
        if length > MAX_BODY:
            self.reply(413, {'error':'PAYLOAD_TOO_LARGE'})
            return
        if self.headers.get('Content-Type', '').split(';')[0].strip().lower() != 'application/json':
            self.reply(415, {'error':'CONTENT_TYPE_REQUIRED'})
            return
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ApiInputError()
            result = process_payload(raw, self.server.app_logger, self.server.audit)
        except ApiInputError as exc:
            self.reply(exc.status, {'error':exc.code})
            return
        except (OSError, ValueError):
            self.reply(400, {'error':'INVALID_PAYLOAD'})
            return
        self.reply(202, result)
    def do_GET(self):
        self.reply(404, {'error':'NOT_FOUND'})

def create_server(port=8765):
    if not 0 <= port <= 65535:
        raise HarnessError('PORT_INVALID')
    try:
        server = HTTPServer(('127.0.0.1', port), ComplaintHandler)
    except OSError:
        raise HarnessError('API_BIND_FAILED') from None
    server.app_logger = logging.getLogger('govcode.synthetic-api')
    server.audit = AuditCounter()
    return server

def serve(port=8765):
    server = create_server(port)
    print(json.dumps({'mode':'local_demo', 'api':'http://127.0.0.1:'+str(server.server_port)+'/complaints',
                      'variant':'fixed-synthetic', 'operational_approval':False}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
