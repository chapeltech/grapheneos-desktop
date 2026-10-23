#!/usr/bin/env python3
"""Capture the unchanged independent auditor's real stdout; no audit substitution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time

ROOT=Path('/u/elric/tree/wonad')
OUTPUT=ROOT/'android/out/native-os37-frozen-audit-8'
AUDITOR=ROOT/'android/tools/audit_os37_frozen_product_8.py'
AUDITOR_SHA='770ae67128034143235e91879708516bbb380ee4928861865105b5a46e7ca592'
BUILD=Path('/srv/wonad-os37-pending-permission-3/recovery-evidence-7/receipt.json')
BUILD_SHA='4eb5acf29d19cecad752575dbf7d2ef63f42b884280f944a5d02e702210dd250'
FREEZE=Path('/srv/wonad-os37-pending-permission-3/frozen-ram/build-receipt.json')
PINS={AUDITOR:AUDITOR_SHA,
 ROOT/'android/platform/freeze-os37-product.py':'0d3e7252eda6995e675739d5d26566ff6569d5af2b9222691213df28dc210bfa',
 Path('/tmp/wonad-os37-pending-permission-recovery-7.py'):'6c000acf150dedb4bedeb3ae444f04d311005b38b08d8465b0b3b6b2290ba5d7',
 ROOT/'android/out/native-shell-build-37-pending-permission-recovery-plan-7.json':'2e48d4ae019780df7f0f69e9e71230c268513200e2115a9ad1de973ce6d48660',
 ROOT/'android/tools/check_native.py':'1d39543b29f8a704c2b73ea27e940c5bdfed50b331766fffdf5c60cfca516ee1',
 BUILD:BUILD_SHA,
 ROOT/'android/tools/audit_os37_frozen_product_6.py':'a7f9a41eb1e1a3d8fac5ae0223972d5b406403dce32b5bb7f3ea7c6c63510c70',
 ROOT/'android/tools/capture_os37_frozen_audit_6.py':'45a180076d78ac338865b5bbccd893dd74dd709e87fd21f48fdf411478fdcf2f',
 ROOT/'android/out/native-os37-frozen-audit-6/receipt.json':'9e74612296fe253ee183ffcdb18c8918298d0f57a4b3bd99d190f5f5af7f2227',
 ROOT/'android/tools/audit_os37_frozen_product_7.py':'88b6539bd7e105843a95551a95465fe58b3b8304e755918337f944fe3ca54440',
 ROOT/'android/tools/capture_os37_frozen_audit_7.py':'9e1e7d754234de749d5d9b984ac3231ecaedf72b8177a6fe90cd1780d6d6e1b6',
 ROOT/'android/out/native-os37-frozen-audit-7/receipt.json':'04d19c2276369c58d807360e458bc52642398fad812ed7222d667f8723c40c98'}
GIB=1024**3
FLOORS={'/':52*GIB,'/var':8*GIB,'/tmp':32*GIB,'/u':GIB//2}
LOSS_CAP=16*1024**2


def require(ok,message):
    if not ok:raise ValueError(message)


def ref(path):
    p=Path(path);require(p.is_file() and not p.is_symlink(),'Exact regular input/output required')
    with p.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(path=str(p),bytes=p.stat().st_size,sha256=sha)


def inputs(expected):
    actual={str(p):ref(p) for p in expected}
    require(all(actual[str(p)]['sha256']==sha for p,sha in expected.items()),'Reviewed small immutable input changed')
    return actual


def resources(before=None,admission=False):
    free={p:shutil.disk_usage(p).free for p in FLOORS}
    require(all(free[p]>=floor+(LOSS_CAP if admission and p=='/u' else 0) for p,floor in FLOORS.items()),
            'Original persistent disk floor/evidence reserve lost')
    if before is not None:require(all(before[p]-free[p]<=LOSS_CAP for p in FLOORS),'Actual bounded evidence interval lost')
    return free


def fresh(path,value):
    with path.open('x') as stream:json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')
    return ref(path)


def capture(argv,directory,expected):
    baseline=resources(admission=True);before=inputs(expected)
    result=dict(schema=1,kind='OS37_independent_audit_actual_stdout_capture',status='not_passed',
        host_pid=os.getpid(),argv=argv,started=time.time(),inputs_before=before,resources_before=baseline,
        runtime_qualified=False,image_qualified=False)
    fresh(directory/'started.json',dict(result));child=None;error=None
    try:
        with (directory/'audit.stdout.json').open('xb') as out,(directory/'audit.stderr').open('xb') as err:
            child=subprocess.Popen(argv,cwd=ROOT,stdout=out,stderr=err,start_new_session=True)
            result['child_pid']=child.pid;fresh(directory/'child-started.json',dict(result))
            while child.poll() is None:
                resources(baseline);time.sleep(2)
            result.update(returncode=child.returncode,child_terminal=time.time())
        result.update(stdout=ref(directory/'audit.stdout.json'),stderr=ref(directory/'audit.stderr'))
        require(child.returncode==0,'Actual unchanged auditor failed')
        value=json.loads((directory/'audit.stdout.json').read_text())
        require(type(value) is dict and value.get('kind')=='OS37_readonly_independent_frozen_product_audit' and
                value.get('host_pid')==child.pid and value.get('runtime_qualified') is False and
                value.get('image_qualified') is False,'Actual child proof JSON identity/scope mismatch')
        result['status']='actual_independent_audit_stdout_captured_not_runtime'
    except BaseException as caught:error=caught;result['primary_error']=repr(caught)
    finally:
        if child is not None and child.poll() is None:
            os.killpg(child.pid,signal.SIGTERM)
            try:child.wait(timeout=10)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait()
        if child is not None:
            result.update(child_pid=child.pid,returncode=child.returncode,child_terminal=time.time(),
                stdout=ref(directory/'audit.stdout.json'),stderr=ref(directory/'audit.stderr'))
        for key,action in (('inputs_after',lambda:inputs(expected)),('resources_after',lambda:resources(baseline))):
            try:result[key]=action()
            except BaseException as caught:
                result.setdefault('completion_errors',[]).append(dict(check=key,error=repr(caught)))
        result['small_immutable_inputs_conserved']=result.get('inputs_after')==before
        if not result['small_immutable_inputs_conserved'] or result.get('completion_errors'):
            result['status']='not_passed'
            if error is None:error=ValueError('Actual capture completion checks failed')
        result['terminal']=time.time();receipt=fresh(directory/'receipt.json',result)
    print(json.dumps(dict(status=result['status'],receipt=receipt)),flush=True)
    if error:raise error
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wrapper-sha',required=True);parser.add_argument('--freeze-receipt-sha',required=True)
    args=parser.parse_args()
    require((os.getuid(),os.getgid())==(1000,1000),'Exact ordinary caller required')
    require(ref(__file__)['sha256']==args.wrapper_sha and len(args.freeze_receipt_sha)==64,'Reviewed literal hashes required')
    require(OUTPUT.parent.resolve(strict=True)==OUTPUT.parent and not os.path.lexists(OUTPUT),'Fresh literal output only')
    expected=dict(PINS);expected[FREEZE]=args.freeze_receipt_sha;expected[Path(__file__)]=args.wrapper_sha
    inputs(expected);resources(admission=True)
    OUTPUT.mkdir(mode=0o700)
    a=OUTPUT.stat();require((a.st_uid,a.st_gid,stat.S_IMODE(a.st_mode))==(1000,1000,0o700),'Private output ownership differs')
    argv=['/usr/bin/python3','-B',str(AUDITOR),'--audit-sha',AUDITOR_SHA,'--build-receipt',str(BUILD),
          '--build-receipt-sha',BUILD_SHA,'--freeze-receipt-sha',args.freeze_receipt_sha]
    capture(argv,OUTPUT,expected)


if __name__=='__main__':main()


