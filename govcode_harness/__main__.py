"""Command line entry point. All executable modes are local demonstrations."""
import argparse
import json
import sys
from . import runtime

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(4, 'error: INVALID_ARGUMENTS\n')

def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == 'project':
        from .project_cli import main as project_main
        return project_main(arguments[1:])
    if arguments and arguments[0] in ('gate', 'evaluate', 'reference-demo', 'control'):
        if arguments[0] == 'gate':
            from .gate import main as dispatch
        elif arguments[0] == 'evaluate':
            from .evaluation import main as dispatch
        elif arguments[0] == 'reference-demo':
            from .reference_cli import main as dispatch
        else:
            control = Parser(prog='python -m govcode_harness control')
            control.add_argument('--config',required=True)
            control.add_argument('--port',type=int,default=8766)
            options = control.parse_args(arguments[1:])
            from .control_plane import serve
            try:
                serve(options.config,port=options.port)
                return 0
            except KeyboardInterrupt:
                return 130
            except Exception:
                print(json.dumps({'outcome':'error','code':'CONTROL_FAILED'}),file=sys.stderr)
                return 4
        return dispatch(arguments[1:])
    parser = Parser(prog='python -m govcode_harness')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('project', help='project profiles, signed rule packs and applicability reference')
    sub.add_parser('control', help='serve a private synthetic reference control configuration')
    sub.add_parser('gate', help='verify current-commit evidence and optional signed reference policy')
    sub.add_parser('evaluate', help='evaluate a synthetic detector corpus')
    sub.add_parser('reference-demo', help='create a private signed synthetic reference demonstration')
    demo = sub.add_parser('demo', help='create a fresh synthetic deny/fix/allow demonstration')
    demo.add_argument('--output', required=True)
    demo.add_argument('--with-iron-laws', action='store_true')
    scan = sub.add_parser('scan', help='scan all tracked files in a clean committed Git snapshot')
    scan.add_argument('--repo', required=True)
    scan.add_argument('--output', required=True)
    scan.add_argument('--parent')
    scan.add_argument('--tenant-id')
    scan.add_argument('--project-id')
    scan.add_argument('--local-demo', action='store_true')
    scan.add_argument('--with-iron-laws', action='store_true')
    scan.add_argument('--commit', help='check only the specified full lowercase 40-character commit SHA; worktree is unchecked')
    verify = sub.add_parser('verify', help='recompute local evidence integrity and decision semantics')
    verify.add_argument('--repo', required=True)
    verify.add_argument('--evidence', required=True)
    verify.add_argument('--tenant-id')
    verify.add_argument('--project-id')
    verify.add_argument('--local-demo', action='store_true')
    verify.add_argument('--commit', help='explicitly verify this same commit snapshot, including historical commits')
    serve = sub.add_parser('serve', help='serve the built-in fixed synthetic complaints API on loopback')
    serve.add_argument('--port', type=int, default=8765)
    serve.add_argument('--local-demo', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'demo':
            report = runtime.demo(args.output, with_iron_laws=args.with_iron_laws)
            print(json.dumps({'mode':'local_demo', 'before':'deny', 'after':'allow',
                'before_run_id':report['before']['run_id'], 'after_run_id':report['after']['run_id'],
                'regression':report['regression'], 'signature_status':'not_signed'}, sort_keys=True))
            return 0
        if args.command == 'scan':
            result = runtime.scan(args.repo, args.output, parent=args.parent, local_demo=args.local_demo, with_iron_laws=args.with_iron_laws, commit=args.commit, tenant_id=args.tenant_id, project_id=args.project_id)
        elif args.command == 'verify':
            result = runtime.verify(args.repo, args.evidence, local_demo=args.local_demo, commit=args.commit, tenant_id=args.tenant_id, project_id=args.project_id)
        else:
            if not args.local_demo:
                raise runtime.HarnessError('LOCAL_DEMO_FLAG_REQUIRED')
            from .sample_api import serve
            serve(args.port)
            return 0
        print(json.dumps(result, sort_keys=True))
        return result['exit_code']
    except runtime.HarnessError as exc:
        print(json.dumps({'outcome':'error', 'code':exc.code}), file=sys.stderr)
        return 4
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps({'outcome':'error', 'code':'RUNTIME_ERROR'}), file=sys.stderr)
        return 4

if __name__ == '__main__':
    raise SystemExit(main())
