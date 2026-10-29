"""Codex adapter for the original Ralph stop hook; no automatic hook claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
LOOP=ROOT/'.runtime/ralph-full'
HOOK=Path.home()/'.codex/plugins/cache/claude-plugins-official/ralph-loop/1.0.1/hooks/stop-hook.sh'
PROMISE='GOVCODE_ROADMAP_APPROVED_SCOPE_COMPLETE'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record',required=True,type=Path)
    parser.add_argument('--complete',action='store_true')
    args=parser.parse_args()
    controller=json.loads((LOOP/'controller.json').read_text())
    if not (LOOP/'.claude/ralph-loop.local.md').exists():raise SystemExit('RALPH_STATE_MISSING')
    record=json.loads(args.record.read_text())
    text=json.dumps(record,ensure_ascii=False,sort_keys=True)
    if '<promise>' in text:raise SystemExit('PROMISE_IN_RECORD_REJECTED')
    if args.complete:
        progress=json.loads((LOOP/'progress.json').read_text())
        # An unanswered scope question does not authorize narrowing the goal.
        if (progress.get('scope_confirmation')!='local_reference' or
            progress.get('user_scope_answer')!='local_reference' or
            progress.get('scope_mode')!='local_reference' or
            progress.get('external_actions_authorized') is not False):
            raise SystemExit('IMPLEMENTATION_SCOPE_UNCONFIRMED')
        if not all(x['implementation']=='complete' and x['acceptance']=='passed' for x in progress['phases'].values()):
            raise SystemExit('ACCEPTANCE_INCOMPLETE')
        proof=json.loads((LOOP/'final-proof.json').read_text())
        if (proof['full_suite']['exit_code']!=0 or proof['full_suite']['tests']<175 or
            proof['full_suite']['failures'] or proof['full_suite']['errors'] or proof['full_suite']['skipped'] or
            proof['final_review']!='APPROVED' or proof['operational_approval'] is not False):
            raise SystemExit('PROOF_INCOMPLETE')
        manifest=json.loads((LOOP/'source-manifest.json').read_text())
        for entry in manifest['files']:
            if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:
                raise SystemExit('SOURCE_CHANGED_AFTER_PROOF')
        result=json.loads((ROOT/proof['reference_result']).read_text())
        if (result['before']['outcome']!='deny' or result['after']['outcome']!='allow' or
            not all(result['store_checks'].values()) or not all(result['control_checks'].values()) or
            result['model_checks']['verdict']!='verified' or not result['model_checks']['sandbox_verified'] or
            not all(result['model_checks']['checks'].values()) or
            result['model_checks']['real_model_executed'] is not False or
            result['operational_approval'] is not False or result['legal_records']!='pending'):
            raise SystemExit('REFERENCE_RESULT_INCOMPLETE')
        if not json.loads((LOOP/'evaluation-confirmatory.json').read_text())['passed']:
            raise SystemExit('EVALUATION_INCOMPLETE')
        text+='\n<promise>'+PROMISE+'</promise>'
    transcript=LOOP/'adapter-transcript.jsonl'
    with transcript.open('a') as stream:
        stream.write(json.dumps({'producer':'codex-ralph-adapter','role':'assistant','message':{'content':[{'type':'text','text':text}]}},ensure_ascii=False,separators=(',',':'))+'\n')
    result=subprocess.run(['bash',str(HOOK)],cwd=LOOP,input=json.dumps({'session_id':controller['session_id'],'transcript_path':str(transcript)}),capture_output=True,text=True,check=True,timeout=10)
    iteration=controller['iteration']
    (LOOP/'hooks').mkdir(exist_ok=True)
    (LOOP/'hooks'/f'iteration-{iteration:03d}.txt').write_text(result.stdout)
    (LOOP/'hooks'/f'iteration-{iteration:03d}.stderr.txt').write_text(result.stderr)
    if (LOOP/'.claude/ralph-loop.local.md').exists():
        response=json.loads(result.stdout)
        prompt=(LOOP/'PROMPT.md').read_text().strip()
        if response.get('decision')!='block' or response.get('reason','').strip()!=prompt:raise SystemExit('RALPH_PROTOCOL_MISMATCH')
        controller['iteration']=iteration+1
        controller['status']='active'
    else:
        if args.complete and ('Detected <promise>'+PROMISE+'</promise>') not in result.stdout:
            raise SystemExit('RALPH_COMPLETION_NOT_CONFIRMED')
        controller['status']='complete' if args.complete else 'limit_or_hook_stop_incomplete'
    controller['last_record_sha256']=hashlib.sha256(args.record.read_bytes()).hexdigest()
    (LOOP/'controller.json').write_text(json.dumps(controller,indent=2)+'\n')
    print(json.dumps({'ralph_iteration':iteration,'next_iteration':controller['iteration'],'status':controller['status']}))

if __name__=='__main__':main()
