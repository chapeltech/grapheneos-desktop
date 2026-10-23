#!/usr/bin/env python3
"""Read-only independent OS37 frozen-product audit; stdout proof, no writes."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

ROOT=Path('/u/elric/tree/wonad')
FREEZER=ROOT/'android/platform/freeze-os37-product.py'
FREEZER_SHA='0d3e7252eda6995e675739d5d26566ff6569d5af2b9222691213df28dc210bfa'
EXECUTOR=Path('/tmp/wonad-os37-pending-permission-recovery-6.py')
EXECUTOR_SHA='93a2033587d3afa3e13739799ea2671a984c602c3defaf3733abd81fe7a1e186'
PLAN=ROOT/'android/out/native-shell-build-37-pending-permission-recovery-plan-6.json'
PLAN_SHA='b056ed30acf6d10ee69a1fc4f42ff18f88777b6f2d990cc90717d2cf1b5ce54a'
MEMBERS=('system/lib64/libstd.dylib.so','system/lib64/liblog_rust.dylib.so',
         'system/lib64/libwonad_input_jni.so','system/framework/services.jar','system/framework/framework.jar',
         'system_ext/lib64/libwonad_broker_jni.so','system_ext/priv-app/SystemUI/SystemUI.apk')


def require(ok,message):
    if not ok:raise ValueError(message)


def ref(path):
    p=Path(path);require(p.is_file() and not p.is_symlink(),'Literal regular file required: '+str(p))
    with p.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(path=str(p),bytes=p.stat().st_size,sha256=digest)


def load(path,sha,name):
    require(ref(path)['sha256']==sha,'Pinned source changed: '+str(path))
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def command(argv,rows,check=True,binary=False):
    started=time.time()
    p=subprocess.Popen(list(map(str,argv)),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out,err=p.communicate(timeout=120)
    rows.append(dict(argv=p.args,pid=p.pid,started=started,terminal=time.time(),returncode=p.returncode,
                     stdout_sha256=hashlib.sha256(out).hexdigest(),stdout_bytes=len(out),
                     stderr_sha256=hashlib.sha256(err).hexdigest(),stderr=err.decode()))
    require(not check or p.returncode==0,'Actual read-only command failed: '+repr(p.args))
    return out if binary else out.decode()


def file_scope(root,names):
    expected=set(names)|{'build-receipt.json'}|{'image-extraction/'+Path(n).name for n in MEMBERS}
    require(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in [root,*root.rglob('*')]),
            'Frozen scope contains alias/special object')
    actual={str(p.relative_to(root)) for p in root.rglob('*') if p.is_file()}
    require(actual==expected,'Frozen18/extracted7 receipt scope changed')


def projected(h,name):
    upper=h.UPPER/name
    chosen=upper if os.path.lexists(upper) else h.LOWER/name
    require(chosen.resolve(strict=True)==chosen,'Aliased actual product projection')
    ref(chosen)
    return chosen


def linear_extents(raw,super_offset):
    result={}
    for name in ('system','system_ext'):
        blocks=re.findall(r'^Name: '+name+r'\n((?:(?!^Name:|^-+).)*?)^-+',raw,re.M|re.S)
        require(len(blocks)==1,'Unique actual '+name+' partition block required')
        parts=blocks[0].split('Extents:\n')
        require(len(parts)==2,'Unique actual partition Extents header required')
        row=re.fullmatch(r'[ \t]*0 \.\. ([0-9]+) linear super ([0-9]+)[ \t]*\n?',parts[1])
        require(row is not None,'Actual sole-linear '+name+' extent required')
        count,sector=map(int,row.groups());require(sector>0,'Invalid actual LP extent')
        result[name]=dict(offset=super_offset+sector*512,bytes=(count+1)*512)
    return result


def copy_commands(rows,h,target,names):
    copies=[r for r in rows if r['argv'] and r['argv'][0]=='cp']
    expected=[['cp','--reflink=never','--sparse=always','--preserve=mode,timestamps',
               str(h.MERGED/name),str(target/name)] for name in names]
    require([r['argv'] for r in copies]==expected and all(r['returncode']==0 and
            r['started']<r['terminal'] for r in copies),'Actual exact18 honest sparse copy commands differ')


def out_preservation(h,build):
    require(build['out_overlay_normally_unmounted'] is True and build['old_out_metadata_conserved'] is True,
            'Actual OUT overlay/lower preservation did not complete')
    current=h.out_metadata(h.OUT_LOWER)
    require(current==build['old_out_metadata_before']==build['old_out_metadata_after'] and
            current['content_rehashed'] is False,'Actual original OUT metadata changed after its closed span')
    return current


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--audit-sha',required=True)
    parser.add_argument('--build-receipt',type=Path,required=True)
    parser.add_argument('--build-receipt-sha',required=True)
    parser.add_argument('--freeze-receipt-sha',required=True)
    args=parser.parse_args()
    require(ref(__file__)['sha256']==args.audit_sha,'Reviewed audit source changed')
    f=load(FREEZER,FREEZER_SHA,'independent_os37_freezer')
    h=load(EXECUTOR,EXECUTOR_SHA,'independent_os37_recovery')
    require(ref(PLAN)['sha256']==PLAN_SHA and ref(args.build_receipt)['sha256']==args.build_receipt_sha,
            'Actual reviewed plan/build receipt required')
    require(args.build_receipt==h.EVIDENCE/'receipt.json','Foreign actual build receipt path')
    target=f.TARGET;freeze_ref=ref(target/'build-receipt.json')
    require(freeze_ref['sha256']==args.freeze_receipt_sha,'Actual reviewed freeze receipt required')
    plan=json.loads(PLAN.read_text());build=json.loads(args.build_receipt.read_text());freeze=json.loads((target/'build-receipt.json').read_text())
    require(plan==h.prepare(),'Current exact source/sealed72/failed lineage changed')
    require(build['executor']==ref(EXECUTOR) and build['plan']==ref(PLAN) and build['phase']=='build' and
            build['status']=='actual_build_passed_only_not_frozen_or_runtime' and
            build['original_products_conserved'] is True and build['product_overlay_normally_unmounted'] is True,
            'Actual successful conserved OS37 build required')
    require(freeze['status']=='actual_frozen_and_packaged_images_verified_not_runtime' and
            freeze['helper']==ref(FREEZER) and freeze['execution_receipt']==ref(args.build_receipt) and
            freeze['executor']==ref(EXECUTOR) and freeze['plan']==ref(PLAN) and freeze['product']==str(target) and
            freeze['build_container']==build['container'] and freeze['overlay_normally_unmounted'] is True and
            freeze['frozen_mount_retained'] is True and freeze['runtime_qualified'] is False and
            not any(k in freeze for k in ('primary_error','cleanup_error','resource_observation_error')),
            'Actual successful private sparse freeze required')
    for p,sha in f.TOOL_PINS.items():require(ref(p)['sha256']==sha,'Actual verifier tool changed')
    h.verify_refs(plan['predecessor_refs']+plan['source']['source_refs']+plan['source']['reviewed_refs']+plan['preflight']['refs'])
    require(h.current_staged_sources(plan)==build['staged_sources_before_m']==build['staged_sources_after_m'],
            'Staged73/platform63 code chain changed')
    require(ref(f.OLD)['sha256']==f.OLD_SHA,'Original exact18 selected set changed')
    original=json.loads(f.OLD.read_text())['files'];names=sorted(original)
    require(len(names)==18 and set(freeze['files'])==set(freeze['source_files_before'])==set(names),'Frozen selected18 mismatch')
    file_scope(target,names);copy_commands(freeze['commands'],h,target,names);rows=[];f.resources()
    info=json.loads(command(['docker','inspect',build['container']],rows))[0]
    h.owned_container(info,plan['build_argv'],build['container']);state=info['State']
    require(state['Status']=='exited' and state['ExitCode']==0 and state['Pid']==0 and not state['Running'] and
            not state['OOMKilled'] and not state['Error'],'Actual successful builder is not stopped')
    for mount,kind,source,mid in ((h.RAM,'tmpfs','wonad-os37-product',build['actual_retained_ram_mount_id']),
                                  (target,'tmpfs','wonad-os37-freeze',freeze['retained_frozen_mount']['id'])):
        raw=json.loads(command(['findmnt','--json','--mountpoint',mount,'-o','ID,TARGET,SOURCE,FSTYPE,OPTIONS'],rows))
        if mount==h.RAM:h.owned_mount(raw,mount,kind,source,expected_id=mid)
        else:
            value=raw['filesystems'];require(len(value)==1 and value[0]['id']==mid and value[0]['target']==str(target) and
                value[0]['source']==source and value[0]['fstype']=='tmpfs' and
                all(s in value[0]['options'].split(',') for s in ('rw','nosuid','nodev','noexec')) and
                os.statvfs(target).f_blocks*os.statvfs(target).f_frsize==f.CAP,'Foreign/replaced frozen RAM mount')
    raw=command(['findmnt','--mountpoint',h.MERGED],rows,check=False)
    require(rows[-1]['returncode']==1 and raw=='','Product overlay remains mounted')
    raw=command(['findmnt','--mountpoint',h.OUT_MERGED],rows,check=False)
    require(rows[-1]['returncode']==1 and raw=='','Generated OUT overlay remains mounted')
    out_metadata=out_preservation(h,build)
    actual={}
    for name in names:
        f.resources();value=ref(target/name);before=freeze['source_files_before'][name];source=projected(h,name)
        require(before['path']==str(h.MERGED/name) and (value['bytes'],value['sha256'])==
                (before['bytes'],before['sha256'])==(freeze['files'][name]['bytes'],freeze['files'][name]['sha256'])==
                (ref(source)['bytes'],ref(source)['sha256']),'Actual frozen/source bytes differ: '+name)
        a,b=(target/name).stat(),source.stat()
        require((a.st_mode,a.st_uid,a.st_gid,a.st_mtime_ns)==(b.st_mode,b.st_uid,b.st_gid,b.st_mtime_ns),
                'Actual frozen/source attributes differ: '+name)
        actual[name]=value
    require(actual['userdata.img']['sha256']==original['userdata.img']['sha256'],'Pristine userdata changed')
    require(actual['system/framework/services.jar']['sha256']!=original['system/framework/services.jar']['sha256'],
            'Changed WMS/NativeBridge still has the old services.jar')
    for name,value in build['retained_upper_image_refs'].items():require(ref(h.UPPER/name)==value,'Actual compiled image changed')
    combined=target/'system-qemu.img';parts=f.gpt(combined)
    for name in ('super','vbmeta'):
        value=ref(projected(h,name+'.img'));require(value['bytes']<=parts[name][1] and
            f.region(combined,parts[name][0],value['bytes'])==value['sha256'],'Actual GPT '+name+' region differs')
    lp=command([h.CHECKOUT/'out/host/linux-x86/bin/lpdump',projected(h,'super.img')],rows)
    images=linear_extents(lp,parts['super'][0])
    for name,image in images.items():
        value=ref(projected(h,name+'.img'));image['sha256']=value['sha256']
        require(value['bytes']==image['bytes'] and f.region(combined,image['offset'],image['bytes'])==value['sha256'] and
                image==freeze['image_proof']['images'][name],'Actual packaged '+name+' differs')
    sys.path.insert(0,str(ROOT/'android/tools'));from check_native import validate,EXPORT_PROFILES
    readelf=next(p for p in f.TOOL_PINS if p.name=='llvm-readobj').with_name('llvm-readelf')
    require(readelf.is_symlink() and os.readlink(readelf)=='llvm-readobj','Actual readelf alias changed')
    extracted={}
    for member in MEMBERS:
        f.resources();partition,relative=member.split('/',1);inside='/'+(member if partition=='system' else relative)
        data=command([h.CHECKOUT/'out/host/linux-x86/bin/debugfs','-R','cat '+inside,projected(h,partition+'.img')],rows,binary=True)
        value=ref(target/'image-extraction'/Path(member).name)
        source_value=actual[member] if member in actual else ref(projected(h,member))
        require((len(data),hashlib.sha256(data).hexdigest())==(value['bytes'],value['sha256'])==
                (source_value['bytes'],source_value['sha256']),
                'Actual packaged/extracted member differs: '+member)
        if member.endswith('.so'):
            text=[command([readelf,flag,'--wide',value['path']],rows) for flag in ('-h','-d','--dyn-syms','-l')]
            profile='broker' if member.endswith('libwonad_broker_jni.so') else 'input' if member.endswith('libwonad_input_jni.so') else None
            require(not validate(*text,'x86_64',EXPORT_PROFILES[profile] if profile else set(),
                                 {'libstd.dylib.so','liblog_rust.dylib.so'}),'Actual packaged Android Rust ELF invalid')
        extracted[member]=value
    stage=json.loads((target/'os-stage.json').read_text())
    require(stage['files']==plan['source']['desired_ledger'] and actual['os-stage.json']['sha256']==build['actual_stage_ledger']['sha256'],
            'Actual frozen source ledger differs')
    f.resources()
    print(json.dumps(dict(schema=1,kind='OS37_readonly_independent_frozen_product_audit',audit=ref(__file__),
        host_pid=os.getpid(),actual_terminal=time.time(),build_receipt=ref(args.build_receipt),freeze_receipt=freeze_ref,
        plan=ref(PLAN),actual_stopped_container=info,actual18=actual,actual_packaged7=extracted,
        actual_gpt=parts,actual_system_extents=images,actual_commands=rows,
        actual_old_out_metadata_only_continuation=out_metadata,
        runtime_qualified=False,image_qualified=False),sort_keys=True))


if __name__=='__main__':main()


