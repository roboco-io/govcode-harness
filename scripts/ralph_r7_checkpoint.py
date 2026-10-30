"""Explicit Codex adapter invoking the original Ralph hook; no automatic hook claim."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
HOOK = Path.home()/'.codex/plugins/cache/claude-plugins-official/ralph-loop/1.0.1/hooks/stop-hook.sh'
PROMISE = 'GOVCODE_R7_LOCAL_REFERENCE_COMPLETE'


def read(path):
    return json.loads(path.read_text())


def require(condition, code):
    if not condition:
        raise ValueError(code)


def inside(root, name):
    path = root/name
    require(not Path(name).is_absolute() and '..' not in Path(name).parts and not path.is_symlink(), 'PROOF_PATH_INVALID')
    require(path.resolve().is_relative_to(root.resolve()), 'PROOF_PATH_INVALID')
    return path


def validate_completion(root, loop):
    progress = read(loop/'progress.json')
    require(progress.get('scope_mode') == 'local_reference' and progress.get('operational_approval') is False, 'SCOPE_INVALID')
    require(set(progress['phases']) == {'R7-F','R7-G','R7-H','R7-I'}, 'PHASES_INCOMPLETE')
    require(all(p.get('implementation') == 'complete' and p.get('acceptance') == 'passed' for p in progress['phases'].values()), 'ACCEPTANCE_INCOMPLETE')
    proof = read(loop/'final-proof.json');suite=proof['full_suite']
    require(type(suite['tests']) is int and suite['tests'] >= 553 and suite['exit_code'] == 0 and not any(suite[k] for k in ('failures','errors','skipped')), 'FULL_SUITE_INCOMPLETE')
    require(proof['final_review'] == 'APPROVED' and proof['installed_package_verified'] is True and proof['operational_approval'] is False, 'PROOF_INCOMPLETE')
    manifest=read(loop/'source-manifest.json')
    require(bool(manifest['files']), 'SOURCE_MANIFEST_EMPTY')
    for item in manifest['files']:
        require(hashlib.sha256(inside(root,item['path']).read_bytes()).hexdigest()==item['sha256'], 'SOURCE_CHANGED_AFTER_PROOF')
    result=read(inside(root,proof['reference_result']))
    require(result.get('operational_approval') is False and result.get('total_requirements')==8 and
            result.get('current_stage_satisfied')==5 and result.get('not_due')==1 and result.get('approved_exclusions')==2,
            'REFERENCE_COUNTS_INVALID')
    require(bool(result.get('checks')) and all(v is True for v in result['checks'].values()), 'REFERENCE_INCOMPLETE')
    return True


def checkpoint(root, loop, record, complete=False):
    controller=read(loop/'controller.json')
    require((loop/'.claude/ralph-loop.local.md').exists(), 'RALPH_STATE_MISSING')
    text=json.dumps(record,ensure_ascii=False,sort_keys=True)
    require('<promise>' not in text, 'PROMISE_IN_RECORD_REJECTED')
    if complete:
        validate_completion(root,loop)
        text+='\n<promise>'+PROMISE+'</promise>'
    transcript=(loop/'adapter-transcript.jsonl').absolute()
    with transcript.open('a') as stream:
        stream.write(json.dumps(dict(producer='codex-ralph-r7-adapter',role='assistant',message=dict(content=[dict(type='text',text=text)])),ensure_ascii=False,separators=(',',':'))+'\n')
    process=subprocess.run(['bash',str(HOOK)],cwd=loop,input=json.dumps(dict(session_id=controller['session_id'],transcript_path=str(transcript))),capture_output=True,text=True,check=True,timeout=10)
    (loop/'hooks').mkdir(exist_ok=True)
    iteration=controller['iteration']
    (loop/'hooks'/f'iteration-{iteration:03d}.txt').write_text(process.stdout)
    (loop/'hooks'/f'iteration-{iteration:03d}.stderr.txt').write_text(process.stderr)
    if (loop/'.claude/ralph-loop.local.md').exists():
        response=json.loads(process.stdout)
        require(response.get('decision')=='block' and response.get('reason','').strip()==(loop/'PROMPT.md').read_text().strip(), 'RALPH_PROTOCOL_MISMATCH')
        controller.update(iteration=iteration+1,status='active')
    else:
        require(not complete or ('Detected <promise>'+PROMISE+'</promise>') in process.stdout, 'RALPH_COMPLETION_UNCONFIRMED')
        controller['status']='complete' if complete else 'limit_or_hook_stop_incomplete'
    controller['last_record_digest']=hashlib.sha256(json.dumps(record,sort_keys=True).encode()).hexdigest()
    (loop/'controller.json').write_text(json.dumps(controller,indent=2)+'\n')
    return dict(ralph_iteration=iteration,next_iteration=controller['iteration'],status=controller['status'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--record',required=True,type=Path);parser.add_argument('--complete',action='store_true')
    args=parser.parse_args()
    print(json.dumps(checkpoint(ROOT,ROOT/'.runtime/ralph-r7',read(args.record),args.complete)))


if __name__=='__main__':main()
