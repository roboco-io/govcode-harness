"""Historical signature/digest verification; never a CI release approval."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',required=True)
    parser.add_argument('--trust',required=True)
    parser.add_argument('--tenant-id',required=True)
    parser.add_argument('--project-id',required=True)
    args=parser.parse_args()
    try:
        from govcode_harness import archive,security
        result=archive.verify_bundle(args.archive,security.read_json(args.trust),args.tenant_id,args.project_id)
        print(json.dumps({key:result[key] for key in ['kind','archive_id','integrity_verified','original_outcome','commit_sha','release_approval']},sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'kind':'archive_integrity','integrity_verified':False,'release_approval':False,'code':getattr(exc,'code','ARCHIVE_INVALID')}))
        return 4

if __name__=='__main__':raise SystemExit(main())
