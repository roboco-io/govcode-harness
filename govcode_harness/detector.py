"""Conservative, bounded, static-call request-to-log analysis.

This is neither a Python interpreter nor whole-program analysis. Unsupported
syntax and calls produce issues, so the caller must refuse a clean decision.
Only explicitly trusted metadata parameters (such as server-generated request_id)
are treated as clean. Other parameters are conservatively input-tainted.
"""
import ast

MAX_SOURCE_BYTES = 256 * 1024
MAX_AST_NODES = 20_000
MAX_HELPER_DEPTH = 16
MAX_HELPER_CALLS = 512
EXCEPTION_TYPES = {'Exception', 'ValueError', 'TypeError', 'RuntimeError', 'KeyError'}
LOG_METHODS = {'info', 'debug', 'warning', 'warn', 'error', 'exception', 'critical', 'fatal', 'log'}
TRUSTED_PARAMETERS = {'request_id', 'logger', 'log', 'logging', 'audit', 'operation', 'result_code', 'status'}
SOURCE_NAMES = {'request', 'request_body', 'payload', 'body', 'phone', 'email', 'address',
                'ssn', 'rrn', 'national_identifier', 'complaint_text'}
SENSITIVE_KEYS = SOURCE_NAMES | {'name', 'resident_registration_number', 'content', 'personal_data'}
PURE_BUILTINS = {'str', 'repr', 'dict', 'list', 'tuple', 'set', 'len', 'int', 'float', 'bool', 'bytes'}
PURE_METHODS = {'format', 'strip', 'lstrip', 'rstrip', 'lower', 'upper', 'encode', 'decode', 'get', 'copy'}


class _Analyzer:
    def __init__(self):
        self.findings = set()
        self.issues = set()
        self.imports = set()
        self.logging_modules = {'logging'}
        self.logging_functions = {}
        self.logger_factories = set()
        self.loggers = {'logger', 'log', 'logging', 'audit'}
        self.helpers = {}
        self.global_env = {}
        self.call_stack = []
        self.helper_calls = 0
        self.returns = []
        self.exception_taint = False
        self.exception_names = set()
        self.raised_taint = False
        self.statements = 0

    def issue(self, node, code):
        self.issues.add((max(1, getattr(node, 'lineno', 1)), code))

    def name(self, node, env):
        if node.id in env:
            return env[node.id]
        if node.id in PURE_BUILTINS or node.id in {'print', '__name__'}:
            return False
        # An unresolved name could be an imported or global source. Never clean.
        self.issue(node, 'UNRESOLVED_NAME')
        return True

    def expr(self, node, env):
        if node is None:
            return False
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Name):
            return self.name(node, env)
        if isinstance(node, ast.Attribute):
            value = self.expr(node.value, env)
            if node.attr.startswith('__'):
                self.issue(node, 'DYNAMIC_ATTRIBUTE')
            return value
        if isinstance(node, ast.Subscript):
            return any([self.expr(node.value, env), self.expr(node.slice, env)])
        if isinstance(node, ast.Slice):
            return any([self.expr(n, env) for n in [node.lower, node.upper, node.step]])
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any([self.expr(n, env) for n in node.elts])
        if isinstance(node, ast.Dict):
            values = [self.expr(n, env) for n in node.values]
            for key in node.keys:
                if key is None:
                    self.issue(node, 'DYNAMIC_MAPPING')
                else:
                    values.append(self.expr(key, env))
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        values.append(key.value.lower() in SENSITIVE_KEYS)
            return any(values)
        if isinstance(node, ast.BinOp):
            return any([self.expr(node.left, env), self.expr(node.right, env)])
        if isinstance(node, ast.UnaryOp):
            return self.expr(node.operand, env)
        if isinstance(node, ast.BoolOp):
            return any([self.expr(n, env) for n in node.values])
        if isinstance(node, ast.Compare):
            return any([self.expr(n, env) for n in [node.left, *node.comparators]])
        if isinstance(node, ast.IfExp):
            return any([self.expr(n, env) for n in [node.test, node.body, node.orelse]])
        if isinstance(node, ast.JoinedStr):
            return any([self.expr(n, env) for n in node.values])
        if isinstance(node, ast.FormattedValue):
            return any([self.expr(node.value, env), self.expr(node.format_spec, env)])
        if isinstance(node, ast.Call):
            return self.call(node, env)
        self.issue(node, 'UNSUPPORTED_EXPRESSION')
        return True

    def call(self, node, env):
        values = []
        for value in node.args:
            if isinstance(value, ast.Starred):
                self.issue(node, 'DYNAMIC_CALL_ARGUMENTS')
                values.append(self.expr(value.value, env))
            else:
                values.append(self.expr(value, env))
        for keyword in node.keywords:
            if keyword.arg is None:
                self.issue(node, 'DYNAMIC_CALL_ARGUMENTS')
            values.append(self.expr(keyword.value, env))
            if (isinstance(node.func, ast.Name) and node.func.id == 'dict'
                    and keyword.arg in SENSITIVE_KEYS):
                values.append(True)
        tainted = any(values)
        func = node.func
        exception_argument = any(isinstance(n, ast.Name) and n.id in self.exception_names
                                 for value in [*node.args, *[k.value for k in node.keywords]]
                                 for n in ast.walk(value))
        if exception_argument and ((isinstance(func, ast.Name) and (func.id in self.logging_functions or func.id == 'print'))
                                   or (isinstance(func, ast.Attribute) and func.attr in LOG_METHODS)):
            self.issue(node, 'EXCEPTION_DETAIL_LOGGING')
        if isinstance(func, ast.Name):
            if func.id in self.logging_functions or func.id == 'print':
                if tainted:
                    self.findings.add(node.lineno)
                else:
                    self.implicit_logging_issue(node, self.logging_functions.get(func.id))
                return False
            if func.id in self.logger_factories:
                if tainted:
                    self.issue(node, 'LOGGER_CONFIGURATION_INPUT_REVIEW')
                return tainted
            if func.id in self.helpers:
                return self.helper(node, env, values)
            if func.id in PURE_BUILTINS or func.id in EXCEPTION_TYPES:
                return tainted
            self.expr(func, env)
        elif isinstance(func, ast.Attribute):
            receiver_tainted = self.expr(func.value, env)
            if func.attr in LOG_METHODS:
                if receiver_tainted or not self.is_logger(func.value):
                    self.issue(node, 'UNANALYSED_LOG_RECEIVER')
                if tainted:
                    self.findings.add(node.lineno)
                else:
                    self.implicit_logging_issue(node, func.attr)
                return False
            if isinstance(func.value, ast.Name) and func.value.id == 'audit' and func.attr == 'record_event':
                if tainted or receiver_tainted:
                    self.issue(node, 'AUDIT_INPUT_REQUIRES_REVIEW')
                return False
            if (isinstance(func.value, ast.Name) and func.value.id in self.logging_modules
                    and func.attr == 'getLogger'):
                if tainted:
                    self.issue(node, 'LOGGER_CONFIGURATION_INPUT_REVIEW')
                return tainted
            if func.attr in {'json', 'get_json', 'get_body'} and receiver_tainted:
                return True
            if func.attr in PURE_METHODS and not (isinstance(func.value, ast.Name)
                    and (func.value.id in self.imports or func.value.id in self.loggers or func.value.id == 'audit')):
                return tainted or receiver_tainted
            tainted = tainted or receiver_tainted
        else:
            self.expr(func, env)
        # Even a zero-argument helper may read a global request and log it.
        self.issue(node, 'UNSUPPORTED_CALL')
        return tainted

    def is_logger(self, node):
        if isinstance(node, ast.Name):
            return node.id in self.loggers or node.id in self.logging_modules
        if isinstance(node, ast.Call):
            func = node.func
            return ((isinstance(func, ast.Name) and func.id in self.logger_factories)
                    or (isinstance(func, ast.Attribute) and func.attr == 'getLogger'
                        and isinstance(func.value, ast.Name) and func.value.id in self.logging_modules))
        return False

    def implicit_logging_issue(self, node, method):
        exception_detail = method == 'exception'
        for keyword in node.keywords:
            literal_false = isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            if keyword.arg == 'exc_info':
                exception_detail = not literal_false
            if keyword.arg == 'stack_info' and not literal_false:
                exception_detail = True
        if exception_detail and self.exception_taint:
            self.findings.add(node.lineno)
        if exception_detail:
            self.issue(node, 'IMPLICIT_EXCEPTION_LOGGING')

    def assign(self, target, value, env, source=None):
        if isinstance(target, ast.Name):
            if target.id in self.helpers or target.id in self.imports or target.id in PURE_BUILTINS or target.id in EXCEPTION_TYPES or target.id == 'print':
                self.issue(target, 'REBINDING_KNOWN_SYMBOL')
            if source is not None and self.is_logger(source):
                self.loggers.add(target.id)
            elif target.id in self.loggers:
                self.issue(target, 'REBOUND_LOGGER_ROLE')
            env[target.id] = value
        else:
            # Container and attribute writes need alias-sensitive analysis.
            self.issue(target, 'UNSUPPORTED_MUTATION')

    def imported(self, node, env):
        supported = ((isinstance(node, ast.Import) and all(alias.name == 'logging' for alias in node.names))
                     or (isinstance(node, ast.ImportFrom) and node.module in {'logging', '__future__'}))
        if not supported:
            self.issue(node, 'UNSUPPORTED_IMPORT')
        for alias in node.names:
            if alias.name == '*':
                self.issue(node, 'WILDCARD_IMPORT')
                continue
            name = alias.asname or (alias.name.split('.')[0] if isinstance(node, ast.Import) else alias.name)
            if name in env:
                self.issue(node, 'REBINDING_KNOWN_SYMBOL')
            self.imports.add(name)
            env[name] = False
            if isinstance(node, ast.Import) and alias.name == 'logging':
                self.logging_modules.add(name)
                self.loggers.add(name)
            if isinstance(node, ast.ImportFrom) and node.module == 'logging':
                if alias.name in LOG_METHODS:
                    self.logging_functions[name] = alias.name
                if alias.name == 'getLogger':
                    self.logger_factories.add(name)

    def block(self, body, env, in_function=False):
        for node in body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            self.statements += 1
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                self.imported(node, env)
            elif isinstance(node, ast.Assign):
                value = self.expr(node.value, env)
                for target in node.targets:
                    self.assign(target, value, env, node.value)
            elif isinstance(node, ast.AnnAssign):
                self.check_annotation(node.annotation)
                if node.value is not None:
                    self.assign(node.target, self.expr(node.value, env), env, node.value)
                elif not isinstance(node.target, ast.Name) or node.target.id not in env:
                    self.issue(node, 'UNINITIALIZED_ANNOTATION')
            elif isinstance(node, ast.AugAssign):
                value = any([self.expr(node.target, env), self.expr(node.value, env)])
                self.assign(node.target, value, env)
            elif isinstance(node, ast.Expr):
                self.expr(node.value, env)
            elif isinstance(node, ast.Return):
                value = self.expr(node.value, env)
                if self.returns:
                    self.returns[-1].append(value)
            elif isinstance(node, ast.Raise):
                self.raised_taint = self.expr(node.exc, env) or self.raised_taint
                if node.cause:
                    self.raised_taint = self.expr(node.cause, env) or self.raised_taint
            elif isinstance(node, ast.Try):
                self.try_block(node, env, in_function)
            elif isinstance(node, ast.If):
                if self.expr(node.test, env):
                    self.issue(node, 'TAINTED_BRANCH_REQUIRES_REVIEW')
                left, right = env.copy(), env.copy()
                self.block(node.body, left, in_function)
                self.block(node.orelse, right, in_function)
                for name in set(left) | set(right):
                    # A branch-local binding may be absent at runtime.
                    if name not in left or name not in right:
                        self.issue(node, 'PARTIAL_BRANCH_BINDING')
                    env[name] = left.get(name, True) or right.get(name, True)
            elif isinstance(node, ast.Pass):
                pass
            elif isinstance(node, ast.FunctionDef):
                self.issue(node, 'NESTED_FUNCTION' if in_function else 'CONDITIONAL_FUNCTION')
            else:
                self.issue(node, 'UNSUPPORTED_STATEMENT')

    def check_annotation(self, annotation):
        if annotation is not None and any(isinstance(n, (ast.Call, ast.NamedExpr)) for n in ast.walk(annotation)):
            self.issue(annotation, 'DYNAMIC_ANNOTATION')

    def function(self, node, global_env):
        local = global_env.copy()
        arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        for argument in arguments:
            self.check_annotation(argument.annotation)
            if argument.arg in self.helpers or argument.arg in self.imports or argument.arg in PURE_BUILTINS or argument.arg in EXCEPTION_TYPES or argument.arg == 'print':
                self.issue(argument, 'SHADOWED_KNOWN_SYMBOL')
            local[argument.arg] = argument.arg not in TRUSTED_PARAMETERS
        self.check_annotation(node.returns)
        if node.args.vararg or node.args.kwarg:
            self.issue(node, 'DYNAMIC_FUNCTION_ARGUMENTS')
        if node.decorator_list:
            self.issue(node, 'DECORATED_FUNCTION')
            for decorator in node.decorator_list:
                self.expr(decorator, global_env)
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults = list(zip(positional[len(positional)-len(node.args.defaults):], node.args.defaults))
        defaults += [(arg, default) for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults) if default]
        for argument, default in defaults:
            default_taint = self.expr(default, global_env)
            local[argument.arg] = local[argument.arg] or default_taint
        self.block(node.body, local, True)

    def helper(self, call, env, values):
        name = call.func.id
        node = self.helpers[name]
        self.helper_calls += 1
        if name in self.call_stack or len(self.call_stack) >= MAX_HELPER_DEPTH or self.helper_calls > MAX_HELPER_CALLS:
            self.issue(call, 'HELPER_ANALYSIS_BOUNDARY')
            return True
        args = [*node.args.posonlyargs, *node.args.args]
        parameters = [*args, *node.args.kwonlyargs]
        bound = {}
        invalid = len(call.args) > len(args) or any(isinstance(a, ast.Starred) for a in call.args)
        for parameter, value in zip(args, values[:len(call.args)]):
            bound[parameter.arg] = value
        for keyword, value in zip(call.keywords, values[len(call.args):]):
            if keyword.arg is None or keyword.arg in bound or keyword.arg not in {p.arg for p in parameters}:
                invalid = True
            bound[keyword.arg] = value
        defaults = dict(zip([p.arg for p in args[len(args)-len(node.args.defaults):]], node.args.defaults))
        defaults.update({p.arg: d for p, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None})
        for parameter in parameters:
            if parameter.arg not in bound:
                if parameter.arg in defaults:
                    bound[parameter.arg] = self.expr(defaults[parameter.arg], self.global_env)
                else:
                    invalid = True
                    bound[parameter.arg] = True
        if invalid or node.decorator_list or node.args.vararg or node.args.kwarg:
            self.issue(call, 'HELPER_CALL_CONTRACT_REVIEW')
        local = self.global_env.copy()
        local.update(bound)
        # Logger identity is a separate role: arbitrary clean values do not make a logger.
        previous_loggers = self.loggers.copy()
        actuals = {parameter.arg: actual for parameter, actual in zip(args, call.args)}
        actuals.update({keyword.arg: keyword.value for keyword in call.keywords if keyword.arg is not None})
        for parameter in parameters:
            actual = actuals.get(parameter.arg)
            if self.is_logger(actual):
                self.loggers.add(parameter.arg)
            else:
                self.loggers.discard(parameter.arg)
        self.call_stack.append(name)
        self.returns.append([])
        self.block(node.body, local, True)
        result = any(self.returns.pop())
        self.call_stack.pop()
        self.loggers = previous_loggers
        return result

    def try_block(self, node, env, in_function):
        # Implicit exceptions can arise at attribute access and logging itself.
        # Explore all handlers. Protected logging and exception output retain review;
        # a handler that emits only fixed metadata does not expose exception detail.
        protected_logging = any(
            isinstance(n, ast.Call) and (
                (isinstance(n.func, ast.Attribute) and n.func.attr in LOG_METHODS)
                or (isinstance(n.func, ast.Name) and (n.func.id in self.logging_functions or n.func.id == 'print')))
            for statement in node.body for n in ast.walk(statement))
        if protected_logging:
            self.issue(node, 'IMPLICIT_EXCEPTION_FLOW_REVIEW')
        previous_raise, previous_exception = self.raised_taint, self.exception_taint
        previous_names = self.exception_names.copy()
        self.raised_taint = False
        normal = env.copy()
        self.block(node.body, normal, in_function)
        explicit_raise = any(isinstance(n, ast.Raise) for statement in node.body for n in ast.walk(statement))
        raised = self.raised_taint if explicit_raise else any(env.values())
        self.block(node.orelse, normal, in_function)
        branches = [normal]
        for handler in node.handlers:
            if handler.type is not None and not (isinstance(handler.type, ast.Name) and handler.type.id in EXCEPTION_TYPES):
                self.issue(handler, 'UNSUPPORTED_EXCEPTION_TYPE')
            caught = env.copy()
            for key, value in normal.items():
                caught[key] = caught.get(key, True) or value
            if handler.name:
                caught[handler.name] = raised
            self.exception_taint = raised
            self.exception_names = previous_names | ({handler.name} if handler.name else set())
            self.block(handler.body, caught, in_function)
            if handler.name:
                caught.pop(handler.name, None)
            branches.append(caught)
        for key in set().union(*(set(branch) for branch in branches)):
            env[key] = any(branch.get(key, True) for branch in branches)
        self.exception_names = previous_names
        self.block(node.finalbody, env, in_function)
        self.raised_taint = previous_raise or raised or self.raised_taint
        self.exception_taint = previous_exception

    def module(self, tree):
        env = {}
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        for node in functions:
            if node.name in env:
                self.issue(node, 'REDEFINED_FUNCTION')
            env[node.name] = False
            if node.name.startswith('_') and not node.name.startswith('__'):
                self.helpers[node.name] = node
        graph = {name: {n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in self.helpers} for name, node in self.helpers.items()}
        def visit(name, active, done):
            if name in active or len(active) >= MAX_HELPER_DEPTH:
                self.issue(self.helpers[name], 'HELPER_ANALYSIS_BOUNDARY')
                return
            if name in done:
                return
            for target in graph[name]:
                visit(target, active | {name}, done)
            done.add(name)
        done = set()
        for name in graph:
            visit(name, set(), done)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id in self.helpers:
                parent = parents.get(node)
                if not (isinstance(parent, ast.Call) and parent.func is node):
                    self.issue(node, 'PRIVATE_HELPER_ESCAPE_REVIEW')
        self.global_env = env
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                self.block([node], env)
        for node in functions:
            # Definition-time behavior is inspected even for private functions.
            for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
                self.check_annotation(argument.annotation)
                if argument.arg in self.helpers or argument.arg in self.imports or argument.arg in PURE_BUILTINS or argument.arg in EXCEPTION_TYPES or argument.arg == 'print':
                    self.issue(argument, 'SHADOWED_KNOWN_SYMBOL')
            self.check_annotation(node.returns)
            if node.name not in self.helpers or node.decorator_list or node.args.vararg or node.args.kwarg:
                self.function(node, env)
            else:
                for default in [*node.args.defaults, *[d for d in node.args.kw_defaults if d is not None]]:
                    self.expr(default, env)
        # A private function with no static caller has no closed caller contract.
        called = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        for name, node in self.helpers.items():
            if name not in called:
                self.issue(node, 'PRIVATE_HELPER_UNCALLED_REVIEW')
                self.function(node, env)
        if not self.statements:
            self.issue(tree, 'EMPTY_ANALYSIS_SCOPE')

    def result(self):
        return {
            'findings': [{'line': line, 'category': 'pii_logging_risk', 'severity': 'high',
                          'data_classes': ['request_body']} for line in sorted(self.findings)],
            'issues': [{'line': line, 'code': code} for line, code in sorted(self.issues)],
            'parsed': True,
        }


def analyze(source: str, path: str) -> dict:
    """Inspect source without executing it; never echo source or path in output."""
    del path  # Runtime owns protected source-location metadata.
    try:
        if not isinstance(source, str):
            raise TypeError
        if len(source.encode('utf-8')) > MAX_SOURCE_BYTES:
            return {'findings': [], 'issues': [{'line': 1, 'code': 'SOURCE_SIZE_LIMIT'}], 'parsed': False}
        tree = ast.parse(source)
        if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
            return {'findings': [], 'issues': [{'line': 1, 'code': 'AST_SIZE_LIMIT'}], 'parsed': False}
        analyzer = _Analyzer()
        analyzer.module(tree)
        return analyzer.result()
    except (SyntaxError, ValueError, TypeError, UnicodeError, RecursionError, MemoryError):
        return {'findings': [], 'issues': [{'line': 1, 'code': 'PYTHON_PARSE_OR_ANALYSIS_ERROR'}], 'parsed': False}
