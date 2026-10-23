#!/usr/bin/env python3
"""Freeze one successful OS37 RAM-overlay build; no build, image or guest launch.

All eighteen files come from the stopped pristine build. RAM copies are real
physical sparse copies, not reflinks. Verify packaged system/system_ext bytes,
including the changed services.jar, before exposing the new frozen product.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path('/u/elric/tree/wonad')
CONTEXT = Path('/srv/wonad-os37-pending-permission-3')
TARGET = CONTEXT / 'frozen-ram'
OLD = Path('/srv/wonad-os36-parked-home-1/product-frozen-2/build-receipt.json')
OLD_SHA = 'd29d9fbe91a33c2e124af878b580601f540a4c35c0ada955f2a44ddc77997bd1'
GIB = 1024**3
CAP = 4*GIB
FLOORS = {'/':52*GIB, '/var':8*GIB, '/tmp':32*GIB, '/u':GIB//2}
TOOL_PINS = {
    ROOT/'android/tools/check_native.py':'1d39543b29f8a704c2b73ea27e940c5bdfed50b331766fffdf5c60cfca516ee1',
    Path('/u/elric/tree/wonad-grapheneos-build/out/host/linux-x86/bin/lpdump'):'3d73bb3350df8f3de0dc9d976c0e308a30022d59324f58162448ad7df2cff989',
    Path('/u/elric/tree/wonad-grapheneos-build/out/host/linux-x86/bin/debugfs'):'a275fce506b342bad7a7fb09c4e58d9617db6d356224bf6cc10d299ae83b5d5e',
    Path('/u/elric/tree/wonad-android-toolchain/android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readobj'):'ef9d7956a96a76fe58e9dc532736a87873454739d154c1217b94249fb36fb5f1',
}


def require(ok, message):
    if not ok: raise ValueError(message)


def ref(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), 'Regular literal artifact required: '+str(path))
    with path.open('rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return dict(path=str(path), bytes=path.stat().st_size, sha256=digest)


def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')


def resources(admission=False):
    free = {p:shutil.disk_usage(p).free for p in FLOORS}
    require(all(free[p] >= floor for p, floor in FLOORS.items()), 'Persistent hard floor lost')
    rows = re.findall(r'^MemAvailable:\s+([0-9]+) kB$', Path('/proc/meminfo').read_text(), re.M)
    require(len(rows)==1 and int(rows[0])*1024 >= (20 if admission else 16)*GIB,
            'Available-memory floor/admission reserve lost')
    return dict(free=free, memory_available=int(rows[0])*1024)


def observed_command(argv, result, guarded=True):
    if guarded: resources()
    start=time.time()
    actual=subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=120)
    result['commands'].append(dict(argv=actual.args,started=start,terminal=time.time(),returncode=actual.returncode,
                                   stdout=actual.stdout,stderr=actual.stderr))
    require(actual.returncode==0,'Actual freezer command failed: '+repr(actual.args))
    return actual.stdout


def region(path, offset, size):
    require(offset >= 0 and size > 0 and offset+size <= path.stat().st_size, 'Invalid image region')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        stream.seek(offset)
        while size:
            block = stream.read(min(size, 4*1024**2)); require(bool(block), 'Truncated image region')
            digest.update(block); size -= len(block)
    return digest.hexdigest()


def gpt(path):
    with path.open('rb') as stream:
        stream.seek(512); header = stream.read(512)
        require(len(header)==512 and header[:8]==b'EFI PART', 'Invalid GPT signature')
        length, crc = struct.unpack_from('<II', header, 12)
        require(92<=length<=512, 'Invalid GPT header size')
        checked = bytearray(header[:length]); checked[16:20] = bytes(4)
        require(zlib.crc32(checked)==crc, 'GPT header CRC mismatch')
        table, count, entry_size, entry_crc = struct.unpack_from('<QIII', header, 72)
        require(0<count<=128 and entry_size==128 and table*512+count*entry_size<=path.stat().st_size,
                'Invalid GPT entry table')
        stream.seek(table*512); entries = stream.read(count*entry_size)
        require(len(entries)==count*entry_size and zlib.crc32(entries)==entry_crc, 'GPT entry CRC mismatch')
    result = {}
    for cursor in range(0,len(entries),entry_size):
        row = entries[cursor:cursor+entry_size]
        if row[:16]==bytes(16): continue
        name = row[56:128].decode('utf-16-le').rstrip('\0')
        first,last = struct.unpack_from('<QQ',row,32)
        require(name not in result and 0<first<=last and (last+1)*512<=path.stat().st_size,
                'Invalid duplicate/out-of-range GPT partition')
        result[name] = (first*512,(last-first+1)*512)
    require(set(result)=={'vbmeta','super'}, 'Unexpected combined-image partitions')
    ordered = sorted(result.values())
    require(ordered[0][0]+ordered[0][1]<=ordered[1][0], 'Overlapping GPT partitions')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    for name in ('helper-sha','executor-sha','plan-sha','execution-receipt-sha'):
        parser.add_argument('--'+name, required=True)
    for name in ('executor','plan','execution-receipt'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    require((os.getuid(),os.getgid())==(1000,1000), 'Ordinary owned caller required')
    require(ref(__file__)['sha256']==args.helper_sha, 'Reviewed freezer source changed')
    for key in ('executor','plan','execution_receipt'):
        require(ref(getattr(args,key))['sha256']==getattr(args,key+'_sha'), 'Reviewed '+key+' changed')
    require(ref(OLD)['sha256']==OLD_SHA, 'Authentic OS36 frozen artifact list changed')
    for path, expected in TOOL_PINS.items(): require(ref(path)['sha256']==expected, 'Verifier tool changed')
    readelf=next(p for p in TOOL_PINS if p.name=='llvm-readobj').with_name('llvm-readelf')
    require(readelf.is_symlink() and os.readlink(readelf)=='llvm-readobj' and
            readelf.resolve(strict=True)==readelf.with_name('llvm-readobj'), 'Exact readelf tool alias changed')
    plan = json.loads(args.plan.read_text()); execution = json.loads(args.execution_receipt.read_text())
    require(plan['context']==str(CONTEXT) and execution['plan']==ref(args.plan) and
            execution['executor']==ref(args.executor) and execution['phase']=='build' and
            execution['status']=='actual_build_passed_only_not_frozen_or_runtime' and
            execution['original_products_conserved'] is True and execution['product_overlay_normally_unmounted'] is True,
            'Successful actual OS37 build required')
    require(not os.path.lexists(TARGET), 'Fresh freezer namespace only')
    spec = importlib.util.spec_from_file_location('actual_os37_freeze_guard',args.executor)
    h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
    require(h.CONTEXT==CONTEXT, 'Foreign executor context')
    h.verify_refs(plan['source']['source_refs']+plan['source']['reviewed_refs']+plan['preflight']['refs'])
    info = json.loads(subprocess.check_output(['docker','inspect',execution['container']],text=True))[0]
    h.owned_container(info,plan['build_argv'],execution['container'])
    state=info['State']
    require(state['Status']=='exited' and state['ExitCode']==0 and state['Pid']==0 and not state['OOMKilled'] and
            not state['Error'] and not state['Running'], 'Original build is not stopped successful')
    require(ref(execution['build_log']['path'])==execution['build_log'], 'Actual compiler log changed')
    require('#### build completed successfully' in Path(execution['build_log']['path']).read_text(), 'Compiler success footer missing')
    ram_raw=json.loads(subprocess.check_output(['findmnt','--json','--mountpoint',str(h.RAM),'-o','ID,TARGET,SOURCE,FSTYPE,OPTIONS'],text=True))
    h.owned_mount(ram_raw,h.RAM,'tmpfs','wonad-os37-product',expected_id=execution['actual_retained_ram_mount_id'])
    require(subprocess.run(['findmnt','--mountpoint',str(h.MERGED)],capture_output=True).returncode==1,
            'Build overlay is unexpectedly mounted')
    resources(admission=True); TARGET.mkdir(mode=0o700)
    result=dict(schema=1,api=3,kind='OS37_honest_RAM_sparse_frozen_product',status='not_passed',
                helper=ref(__file__),host_pid=os.getpid(),execution_receipt=ref(args.execution_receipt),
                plan=ref(args.plan),executor=ref(args.executor),commands=[],files={},runtime_qualified=False)
    overlay_id=None; frozen_id=None; error=None
    def command(argv, guarded=True):
        return observed_command(argv,result,guarded=guarded)
    def mount_record(path, guarded=True):
        raw=json.loads(command(['findmnt','--json','--mountpoint',path,'-o','ID,TARGET,SOURCE,FSTYPE,OPTIONS'],guarded=guarded))
        require(len(raw['filesystems'])==1 and raw['filesystems'][0]['target']==str(path),'Ambiguous owned mount')
        return raw
    try:
        command(['sudo','-n','mount','-t','tmpfs','-o','size=4G,nosuid,nodev,noexec,mode=0700,uid=1000,gid=1000',
                 'wonad-os37-freeze',TARGET])
        row=mount_record(TARGET)['filesystems'][0]; frozen_id=row['id']
        require(row['fstype']=='tmpfs' and shutil.disk_usage(TARGET).total==CAP,'Exact four-GiB frozen mount missing')
        result['retained_frozen_mount']=row
        options='lowerdir='+str(h.LOWER)+',upperdir='+str(h.UPPER)+',workdir='+str(h.WORK)+',index=off,metacopy=off,redirect_dir=off'
        command(['sudo','-n','mount','-t','overlay','overlay','-o',options,h.MERGED])
        raw=mount_record(h.MERGED)
        row=h.owned_mount(raw,h.MERGED,'overlay','overlay',
                          dict(lowerdir=h.LOWER,upperdir=h.UPPER,workdir=h.WORK),semantic=False)
        overlay_id=row['id']
        h.owned_mount(raw,h.MERGED,'overlay','overlay',dict(lowerdir=h.LOWER,upperdir=h.UPPER,workdir=h.WORK),overlay_id)
        for value in execution['actual_product_image_refs'].values(): require(ref(value['path'])==value,'Actual build image changed')
        names=sorted(json.loads(OLD.read_text())['files'])
        require(len(names)==18,'Exact original eighteen-artifact set required')
        result['source_files_before']={name:ref(h.MERGED/name) for name in names}
        for name,before in result['source_files_before'].items():
            target=TARGET/name; target.parent.mkdir(parents=True,exist_ok=True)
            source=h.MERGED/name; attrs=source.lstat()
            command(['cp','--reflink=never','--sparse=always','--preserve=mode,timestamps',source,target])
            actual=ref(target)
            require((actual['bytes'],actual['sha256'])==(before['bytes'],before['sha256']) and ref(source)==before,
                    'Frozen/source bytes changed: '+name)
            copied=target.lstat()
            require((copied.st_mode,copied.st_uid,copied.st_gid,copied.st_mtime_ns)==
                    (attrs.st_mode,attrs.st_uid,attrs.st_gid,attrs.st_mtime_ns),'Frozen attributes differ')
            result['files'][name]=dict(sha256=actual['sha256'],bytes=actual['bytes'],allocated_bytes=copied.st_blocks*512)
            require(shutil.disk_usage(TARGET).free>=128*1024**2,'Frozen RAM output reserve lost')
        stage=json.loads((TARGET/'os-stage.json').read_text())
        require(stage['files']==plan['source']['desired_ledger'] and
                ref(TARGET/'os-stage.json')['sha256']==execution['actual_stage_ledger']['sha256'], 'Frozen staged source ledger differs')
        combined=TARGET/'system-qemu.img'; parts=gpt(combined)
        for name in ('super','vbmeta'):
            original=h.MERGED/(name+'.img'); value=ref(original)
            require(value['bytes']<=parts[name][1] and region(combined,parts[name][0],value['bytes'])==value['sha256'],
                    'Combined image differs from actual '+name)
        lp=command([h.CHECKOUT/'out/host/linux-x86/bin/lpdump',h.MERGED/'super.img'])
        images={}
        for name in ('system','system_ext'):
            match=re.search(r'Name: '+name+r'\n.*?Extents:\n\s*0 \.\. (\d+) linear super (\d+)\n-+',lp,re.S)
            require(match is not None,'Missing sole linear '+name+' extent')
            size=(int(match[1])+1)*512; offset=parts['super'][0]+int(match[2])*512
            source=h.MERGED/(name+'.img'); value=ref(source)
            require(value['bytes']==size and region(combined,offset,size)==value['sha256'],'Packaged '+name+' mismatch')
            images[name]=dict(path=source,offset=offset,bytes=size,sha256=value['sha256'])
        extracted=TARGET/'image-extraction'; extracted.mkdir(mode=0o700)
        members=('system/lib64/libstd.dylib.so','system/lib64/liblog_rust.dylib.so',
                 'system/lib64/libwonad_input_jni.so','system/framework/services.jar','system/framework/framework.jar',
                 'system_ext/lib64/libwonad_broker_jni.so','system_ext/priv-app/SystemUI/SystemUI.apk')
        sys.path.insert(0,str(ROOT/'android/tools')); from check_native import validate,EXPORT_PROFILES
        dependencies={'libstd.dylib.so','liblog_rust.dylib.so'}
        for member in members:
            partition,relative=member.split('/',1); target=extracted/Path(member).name
            inside='/'+(member if partition=='system' else relative)
            command([h.CHECKOUT/'out/host/linux-x86/bin/debugfs','-R','dump '+inside+' '+str(target),images[partition]['path']])
            require(ref(target)['sha256']==ref(h.MERGED/member)['sha256'],'Packaged member mismatch: '+member)
            if target.suffix=='.so':
                raw=[command([readelf,flag,'--wide',target]) for flag in ('-h','-d','--dyn-syms','-l')]
                profile='broker' if target.name=='libwonad_broker_jni.so' else 'input' if target.name=='libwonad_input_jni.so' else None
                errors=validate(*raw,'x86_64',EXPORT_PROFILES[profile] if profile else set(),dependencies)
                require(not errors,'Packaged Android ELF invalid: '+repr(errors))
        result['image_proof']=dict(gpt_crc_verified=True,super_vbmeta_regions_verified=True,
                                  system_and_system_ext_regions_verified=True,packaged_members=list(members),
                                  android_rust_elf_validation='passed',images={k:{n:v for n,v in x.items() if n!='path'} for k,x in images.items()})
        require({name:ref(h.MERGED/name) for name in names}==result['source_files_before'],'Source product changed during freeze')
        result.update(status='actual_frozen_and_packaged_images_verified_not_runtime',os_build='passed',
                      product=str(TARGET),build_container=execution['container'],stage_sha256=ref(TARGET/'os-stage.json')['sha256'],
                      fingerprint=(TARGET/'build_fingerprint-sdk_phone64_x86_64.txt').read_text().strip(),
                      copy=dict(method='cp --reflink=never --sparse=always --preserve=mode,timestamps',
                                mandatory_same_filesystem_cow=False,pristine_build_userdata=True,guest_userdata_copied=False))
    except BaseException as caught:
        error=caught; result['primary_error']=repr(caught)
    finally:
        if overlay_id is not None:
            try:
                h.owned_mount(mount_record(h.MERGED,guarded=False),h.MERGED,'overlay','overlay',
                              dict(lowerdir=h.LOWER,upperdir=h.UPPER,workdir=h.WORK),overlay_id,semantic=False)
                command(['sudo','-n','umount',h.MERGED],guarded=False); result['overlay_normally_unmounted']=True
            except BaseException as caught: result['cleanup_error']=repr(caught)
        result['terminal']=time.time()
        try: result['resources_after']=resources()
        except BaseException as caught: result['resource_observation_error']=repr(caught)
        if result.get('cleanup_error') or result.get('resource_observation_error'):
            result['status']='not_passed'
        result['frozen_mount_retained']=frozen_id is not None
        save(TARGET/'build-receipt.json',result)
        print(json.dumps(dict(receipt=ref(TARGET/'build-receipt.json'),product=str(TARGET),status=result['status'])),flush=True)
    if error: raise error
    require(result.get('overlay_normally_unmounted') and not result.get('cleanup_error') and
            not result.get('resource_observation_error'),'Owned overlay cleanup/resource check failed')


if __name__=='__main__': main()
