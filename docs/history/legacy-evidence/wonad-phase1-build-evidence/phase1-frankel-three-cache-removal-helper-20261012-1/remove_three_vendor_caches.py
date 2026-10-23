#!/usr/bin/python3
"""PREPARED ONLY: exact WORK6/7/8 cache exception; root/user GO still required."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import time
import types

sys.dont_write_bytecode=True

BASE = Path('/u/elric/tree/wonad-phase1-build-evidence')
HERE = Path(__file__).resolve().parent
AUDIT = BASE/'phase1-frankel-failed-work-cache-audit-20261012-1'
SOURCE = Path('/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1')
OUTPUT = BASE/'phase1-frankel-three-cache-pruning-20261012-1'
AUTHORIZATION = BASE/'phase1-frankel-three-cache-cleanup-root-authorization-20261012-1.json'
TARGETS = (
    BASE/'phase1-frankel-vendor-cache-work-20261012-6/unpacked/frankel-CP3A.261005.005-tmp',
    BASE/'phase1-frankel-vendor-cache-work-20261012-7/unpacked/frankel-CP3A.261005.005-tmp',
    BASE/'phase1-frankel-vendor-cache-work-20261012-8/unpacked/frankel-CP3A.261005.005-tmp',
)
OWNER_SHA = '275c378a564ed3ccb107cd93fc670168166ba37ff9391d17757aabeaae93fc6a'
AUDIT_SHA = 'b2abe8cdabc01dbbde344a760d74a08213e07d459a0d615c184fb0b281dcbfbd'
DOCKER = ['/usr/bin/docker','--host','unix:///var/run/docker.sock']
DIRECTORY_FLAGS = os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
READ_FLAGS = os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC

def require(ok, reason):
    if not ok: raise ValueError(reason)

def unique(pairs):
    value = {}
    for key,item in pairs:
        require(key not in value,'Duplicate JSON key')
        value[key] = item
    return value

def metadata(s, path):
    return {'path':str(path),'device':s.st_dev,'inode':s.st_ino,'uid':s.st_uid,'gid':s.st_gid,
            'mode':stat.S_IMODE(s.st_mode),'file_type':stat.S_IFMT(s.st_mode),'nlink':s.st_nlink,
            'bytes':s.st_size,'allocated_bytes':s.st_blocks*512,
            'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns}

def opened_directory(path):
    """Open every absolute component without following any symlink."""
    require(path.is_absolute() and path==Path(os.path.normpath(path)), 'Noncanonical directory')
    fd = os.open('/',DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            new = os.open(component,DIRECTORY_FLAGS,dir_fd=fd)
            os.close(fd); fd = new
        return fd
    except BaseException:
        os.close(fd); raise

def read_regular(path, expected_sha=None, limit=32*1024**2):
    parent = opened_directory(path.parent)
    fd = None
    try:
        fd = os.open(path.name,READ_FLAGS,dir_fd=parent); before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,
                'Not a bounded single-link regular evidence input')
        raw = bytearray()
        while len(raw)<before.st_size:
            chunk = os.read(fd,min(65536,before.st_size-len(raw)))
            require(bool(chunk),'Short evidence input'); raw.extend(chunk)
        require(metadata(before,path)==metadata(os.fstat(fd),path),'Evidence input changed')
        require(metadata(before,path)==metadata(os.stat(path.name,dir_fd=parent,follow_symlinks=False),path),
                'Evidence input path replaced')
        digest = hashlib.sha256(raw).hexdigest()
        require(expected_sha is None or digest==expected_sha,'Evidence input hash differs')
        return bytes(raw),dict(metadata(before,path),sha256=digest)
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)

def load(path, expected_sha=None):
    raw,ref = read_regular(path,expected_sha)
    return json.loads(raw,object_pairs_hook=unique),ref

def identity_equal(actual, expected):
    return all(actual[k]==expected[k] for k in ('path','device','inode','uid','gid','mode','file_type'))

def authenticated_inputs():
    owner,owner_ref=load(AUDIT/'owner-record.json',OWNER_SHA)
    for name,ref in owner['refs'].items():
        require(Path(ref['path'])==AUDIT/name,'Audit reference escaped exact directory')
        raw,current=read_regular(AUDIT/name,ref['sha256'])
        require(len(raw)==ref['bytes'],'Audit reference size differs')
    source_bytes,_=read_regular(AUDIT/'audit.py',AUDIT_SHA)
    audit=types.ModuleType('pinned_readonly_cache_audit')
    audit.__file__=str(AUDIT/'audit.py')
    exec(compile(source_bytes,audit.__file__,'exec'),audit.__dict__)
    summary,_=load(AUDIT/'summary-observation.json',owner['refs']['summary-observation.json']['sha256'])
    attempts=[]
    for generation,target in zip((7,8,9),TARGETS):
        row,_=load(AUDIT/f'g{generation}-observation.json',owner['refs'][f'g{generation}-observation.json']['sha256'])
        attempt=row['attempt']
        require(Path(attempt['cache_census']['root']['path'])==target,'Target custody differs')
        preflight,_=load(Path(attempt['references']['preflight']['path']),attempt['references']['preflight']['sha256'])
        result,_=load(Path(attempt['references']['result']['path']),attempt['references']['result']['sha256'])
        lock,_=load(Path(attempt['references']['lock']['path']),attempt['references']['lock']['sha256'])
        require(result['work']==preflight['reflink_workspace'] and preflight['nonce']==result['container']['nonce'] and
                lock['source']==str(SOURCE) and lock['container']==result['container']['name'], 'Original custody joins differ')
        require(preflight['create_argv'][preflight['create_argv'].index('--name')+1]==result['container']['name'],
                'Original container name differs')
        attempts.append((attempt,preflight,result))
    return audit,summary,attempts,owner_ref

def authorization(args):
    require(args.execute_after_explicit_cache_exception_and_root_review,
            'No cache removal without explicit user exception and root review')
    for digest in (args.reviewed_helper_sha256,args.authorization_sha256):
        require(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'Explicit exact SHA required')
    _,helper_ref=read_regular(Path(__file__).resolve(),args.reviewed_helper_sha256)
    auth,auth_ref=load(AUTHORIZATION,args.authorization_sha256)
    require(set(auth)=={'schema','kind','user_exception','scope','targets','source','audit_owner_sha256',
                      'helper_sha256','host_tests_sha256'},'Unknown authorization grammar')
    require(type(auth['schema']) is int and auth['schema']==1 and
            auth['kind']=='phase1_exact_three_interrupted_vendor_cache_cleanup_authorization_v1' and
            auth['user_exception'] is True and auth['scope']=='discard_only_interrupted_extraction_bytes_preserve_all_other_custody' and
            auth['targets']==list(map(str,TARGETS)) and auth['source']==str(SOURCE) and
            auth['audit_owner_sha256']==OWNER_SHA and auth['helper_sha256']==args.reviewed_helper_sha256,
            'Authorization scope/pins differ')
    read_regular(HERE/'test_remove_three_vendor_caches.py',auth['host_tests_sha256'])
    return auth_ref,helper_ref

def mount_id(fd):
    text=Path(f'/proc/self/fdinfo/{fd}').read_text()
    rows=re.findall(r'^mnt_id:\s+([0-9]+)$',text,re.M)
    require(len(rows)==1,'Unique fd mount ID required')
    return int(rows[0])

def no_mounted_targets(text,targets):
    for line in text.splitlines():
        fields=line.split(' ')
        require(len(fields)>=10 and ' - ' in line,'Malformed mountinfo')
        value=fields[4]
        require(not re.search(r'\\(?!040|011|012|134)',value),'Malformed mountpoint escape')
        value=re.sub(r'\\(040|011|012|134)',lambda m:chr(int(m[1],8)),value)
        point=Path(value)
        require(not any(point==target or target in point.parents for target in targets),
                'Target or descendant is mounted')

def fiemap_fd(fd):
    start=0;extents=[]
    while True:
        buffer=bytearray(32+56*256)
        struct.pack_into('<QQIIII',buffer,0,start,(1<<64)-1-start,0,0,256,0)
        fcntl.ioctl(fd,0xC020660B,buffer,True)
        count=struct.unpack_from('<QQIIII',buffer)[3]
        require(count<=256,'Bad extent count')
        batch=[struct.unpack_from('<QQQQQIIII',buffer,32+56*i) for i in range(count)]
        for e in batch:
            require(e[2]>0 and e[0]>=start and e[3:5]==(0,0) and e[6:]==(0,0,0),'Bad extent')
            extents.append({'logical':e[0],'physical':e[1],'bytes':e[2],'flags':e[5]})
        require(len(extents)<=8192,'Extent bound exceeded')
        if not batch or batch[-1][5]&1:break
        end=batch[-1][0]+batch[-1][2];require(end>start,'Extent no progress');start=end
    uncertain=0x2|0x4|0x8|0x80|0x100|0x200|0x400
    return {'extent_count':len(extents),'extent_flags':sorted({e['flags'] for e in extents}),
            'mapped_bytes':sum(e['bytes'] for e in extents),
            'shared_extent_bytes':sum(e['bytes'] for e in extents if e['flags']&0x2000),
            'observed_unshared_extent_bytes':sum(e['bytes'] for e in extents if not e['flags']&(0x2000|uncertain)),
            'extent_ledger_sha256':hashlib.sha256(json.dumps(extents,sort_keys=True,separators=(',',':')).encode()).hexdigest()}

def fd_census(fd, path, expected, root_mount=None):
    """No-follow exact old census, including current regular-file FIEMAP."""
    root_mount=mount_id(fd) if root_mount is None else root_mount
    rows={row['relative_path']:row for row in expected}
    require(len(rows)==len(expected)<=1000 and '.' in rows,'Invalid exact census')
    seen=set();visited=set()
    def walk(directory,relative,depth):
        require(depth<=20,'Depth bound exceeded')
        current=metadata(os.fstat(directory),path/relative)
        old=rows.get(relative)
        require(old is not None and current=={k:v for k,v in old.items() if k not in ('relative_path','fiemap','opaque_symlink_target')},
                'Directory metadata changed')
        require(mount_id(directory)==root_mount and current['uid']==current['gid']==1000,'Directory mount/owner differs')
        key=(current['device'],current['inode']);require(key not in seen,'Inode alias');seen.add(key);visited.add(relative)
        for name in sorted(os.listdir(directory)):
            require(name not in ('.','..') and '/' not in name,'Bad child name')
            child=name if relative=='.' else relative+'/'+name
            old=rows.get(child);require(old is not None,'Unexpected cache entry')
            s=os.stat(name,dir_fd=directory,follow_symlinks=False);m=metadata(s,path/child)
            require(m=={k:v for k,v in old.items() if k not in ('relative_path','fiemap','opaque_symlink_target')},'Cache metadata changed')
            require(m['uid']==m['gid']==1000 and m['device']==current['device'],'Cache owner/device differs')
            if stat.S_ISDIR(s.st_mode):
                child_fd=os.open(name,DIRECTORY_FLAGS,dir_fd=directory)
                try:walk(child_fd,child,depth+1)
                finally:os.close(child_fd)
            else:
                key=(m['device'],m['inode']);require(key not in seen,'Inode alias');seen.add(key);visited.add(child)
                if stat.S_ISREG(s.st_mode):
                    require(s.st_nlink==1,'Hardlinked cache file')
                    child_fd=os.open(name,READ_FLAGS,dir_fd=directory)
                    try:
                        require(metadata(os.fstat(child_fd),path/child)==m and mount_id(child_fd)==root_mount,'File replaced/mounted')
                        require(fiemap_fd(child_fd)==old['fiemap'],'Cache extent census changed')
                        require(metadata(os.fstat(child_fd),path/child)==m,'File changed during census')
                    finally:os.close(child_fd)
                elif stat.S_ISLNK(s.st_mode):
                    require(os.readlink(name,dir_fd=directory)==old['opaque_symlink_target'],'Opaque symlink changed')
                else:raise ValueError('Special cache file')
        require(metadata(os.fstat(directory),path/relative)==current,'Directory changed during census')
    walk(fd,'.',0)
    require(visited==set(rows),'Missing expected cache entry')
    return rows

def docker_read(*args):
    run=subprocess.run([*DOCKER,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,
                       env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},check=False)
    require(run.returncode==0 and not run.stderr and len(run.stdout)<=1024**2,'Bounded Docker observation failed')
    return run.stdout

def no_competing_writer():
    raw=docker_read('ps','--quiet','--no-trunc')
    identities=raw.decode().splitlines()
    require(len(identities)<=100 and len(identities)==len(set(identities)) and
            all(re.fullmatch('[0-9a-f]{64}',value) for value in identities),'Malformed live container census')
    observations=[]
    protected=[SOURCE]+[target.parent.parent for target in TARGETS]
    for identity in identities:
        values=json.loads(docker_read('inspect','--type','container',identity),object_pairs_hook=unique)
        require(isinstance(values,list) and len(values)==1 and values[0]['Id']==identity,'Live container census identity changed')
        info=values[0]
        require(isinstance(info.get('Mounts'),list),'Missing live mount inventory')
        for mount in info['Mounts']:
            require(type(mount.get('RW')) is bool and isinstance(mount.get('Source'),str),'Malformed live mount')
            if mount['RW']:
                bound=Path(mount['Source']).resolve(strict=True)
                require(not any(bound==p or bound in p.parents or p in bound.parents for p in protected),
                        'Live container can write source/cache custody')
        observations.append({'id':identity,'state':info['State'],'mounts':info['Mounts']})
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name)==os.getpid():continue
        try:
            with (entry/'cmdline').open('rb') as stream:payload=stream.read(65537)
        except (FileNotFoundError,ProcessLookupError):continue
        require(len(payload)<=65536 and (not payload or payload.endswith(b'\0')),'Unbounded/malformed live argv')
        if not payload:continue
        names=[Path(value.decode('utf-8',errors='strict')).name for value in payload[:-1].split(b'\0')]
        require(not any(name in ('run_frankel_vendor.py','generate-frankel-vendor.sh') or
            re.fullmatch(r'phase1_frankel_vendor(?:_cache)?_driver_[0-9_]+\.py',name) or
            re.fullmatch(r'prepare-phase1-frankel-vendor(?:-cache)?-[0-9-]+\.sh',name) for name in names),
            'Live vendor process present')
    return observations

def protected_snapshot(summary, attempts):
    paths={}
    for attempt,preflight,result in attempts:
        for name,ref in attempt['references'].items():
            raw,current=read_regular(Path(ref['path']),ref['sha256']);require(len(raw)==ref['bytes'],'Protected ref size differs')
            paths[ref['path']]=current
        for row in (attempt['work'],attempt['unpacked_directory_preserved'],attempt['archive_preserved']):
            path=Path(row['path']);fd=opened_directory(path) if row['file_type']==stat.S_IFDIR else None
            try:
                m=metadata(os.fstat(fd) if fd is not None else os.lstat(path),path)
                require(identity_equal(m,row),'Protected root/archive identity differs')
                if row['file_type']==stat.S_IFREG:require(m==row,'Protected ZIP metadata changed')
                paths[str(path)]=m
            finally:
                if fd is not None:os.close(fd)
        require(sorted(os.listdir(attempt['work']['path']))==[
            'frankel-cp3a.261005.005-factory-3721e6ac.zip','unpacked'],'WORK sibling inventory differs')
        for row in result['inputs']['source_directory_identities'].values():
            m=metadata(os.lstat(row['path']),row['path'])
            require(all(m[k]==row[k] for k in ('path','device','inode','uid','gid','mode')),'Original source root identity differs')
            paths[row['path']]=m
        for row in (result['inputs']['cache']['directory'],result['inputs']['cache']['archive']):
            m=metadata(os.lstat(row['path']),row['path'])
            require(all(m[k]==row[k] for k in ('path','device','inode','uid','gid','mode')),'Canonical factory custody differs')
            paths[row['path']]=m
        cli=preflight['docker_authority']['cli']
        require(cli['path']==cli['realpath']=='/usr/bin/docker','Original Docker CLI path differs')
        raw,current=read_regular(Path(cli['path']),cli['file']['sha256'])
        require(len(raw)==cli['file']['size'],'Original Docker CLI size differs')
        for key in ('device','inode','uid','gid'):
            require(current[key]==cli[key],'Original Docker CLI identity differs')
        require(current['file_type']==stat.S_IFREG and current['mode']==stat.S_IMODE(cli['mode']),
                'Original Docker CLI file mode differs')
        paths[cli['path']]=current
        socket=preflight['docker_authority']['socket']
        current=metadata(os.stat(socket['path']),socket['path'])
        require(all(current[k]==socket[k] for k in ('device','inode','uid','gid')) and
                current['mode']==stat.S_IMODE(socket['mode']) and
                current['file_type']==stat.S_IFSOCK and os.path.realpath(socket['path'])==socket['realpath'],
                'Original local Docker socket identity differs')
    for ref in summary['current_source_inputs'].values():
        raw,current=read_regular(Path(ref['path']),ref['sha256']);require(len(raw)==ref['bytes'],'Source pin size differs')
        paths[ref['path']]=current
    ref=summary['factory_cache_receipt'];raw,current=read_regular(Path(ref['path']),ref['sha256'])
    require(len(raw)==ref['bytes'],'Factory receipt size differs');paths[ref['path']]=current
    return paths

def compare_protected(before, after):
    require(set(before)==set(after),'Protected set changed')
    for path,old in before.items():
        new=after[path]
        if old['file_type']==stat.S_IFDIR:
            require(identity_equal(new,old),'Protected directory identity changed')
        else:require(new==old,'Protected evidence/archive/source changed')

def fresh_stop_proofs(audit,attempts):
    proofs=[]
    for attempt,preflight,result in attempts:
        proof=audit.inspect_old(preflight,result)
        # A restarted-and-stopped historical container is not original custody.
        # Exact original nonce/profile remains necessary but is not sufficient.
        require(proof['state']==attempt['container']['state'],'Historical container state/timestamps changed')
        proofs.append(proof)
    return proofs

def write_new(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        raw=json.dumps(value,sort_keys=True,indent=2).encode()+b'\n'
        with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
    finally:os.close(fd)
    parent=opened_directory(path.parent)
    try:os.fsync(parent)
    finally:os.close(parent)

def remove_exact(parent, name, target, rows, journal, removed):
    """Only entries already admitted by the complete exact fd census."""
    require(target in TARGETS and name==target.name,'Removal escaped literal allowlist')
    mount=mount_id(parent)
    def log(relative,old,kind):
        item={'target':str(target),'relative_path':relative,'kind':kind,
              'device':old['device'],'inode':old['inode'],'allocated_bytes_before':old['allocated_bytes']}
        # Preserve the already-completed removal even if persistent journaling fails.
        removed.append(item)
        journal.write(json.dumps(item,sort_keys=True)+'\n');journal.flush();os.fsync(journal.fileno())
    def erase(directory,relative,depth):
        require(depth<=20,'Removal depth exceeded')
        expected_children=sorted(Path(key).name for key in rows if key!='.' and
            str(Path(key).parent)==('.' if relative=='.' else relative))
        require(sorted(os.listdir(directory))==expected_children,'Removal sibling inventory changed')
        for child in expected_children:
            key=child if relative=='.' else relative+'/'+child;old=rows[key]
            current=metadata(os.stat(child,dir_fd=directory,follow_symlinks=False),target/key)
            require(identity_equal(current,old),'Entry changed before removal')
            no_mounted_targets(Path('/proc/self/mountinfo').read_text(),TARGETS)
            if old['file_type']==stat.S_IFDIR:
                child_fd=os.open(child,DIRECTORY_FLAGS,dir_fd=directory)
                try:
                    require(mount_id(child_fd)==mount and identity_equal(metadata(os.fstat(child_fd),target/key),old),'Directory replaced/mounted')
                    erase(child_fd,key,depth+1)
                finally:os.close(child_fd)
                require(identity_equal(metadata(os.stat(child,dir_fd=directory,follow_symlinks=False),target/key),old),'Directory replaced before rmdir')
                os.rmdir(child,dir_fd=directory);log(key,old,'directory')
            else:
                require(current=={k:v for k,v in old.items() if k not in ('relative_path','fiemap','opaque_symlink_target')},'File metadata changed before unlink')
                require(old['file_type'] in (stat.S_IFREG,stat.S_IFLNK),'Special file removal refused')
                require(old['file_type']!=stat.S_IFREG or current['nlink']==1,'Hardlink removal refused')
                if old['file_type']==stat.S_IFLNK:
                    require(os.readlink(child,dir_fd=directory)==old['opaque_symlink_target'],'Symlink changed before unlink')
                os.unlink(child,dir_fd=directory);log(key,old,'regular' if old['file_type']==stat.S_IFREG else 'opaque_symlink')
        require(not os.listdir(directory),'Directory not empty after exact removals')
    fd=os.open(name,DIRECTORY_FLAGS,dir_fd=parent)
    try:
        require(mount_id(fd)==mount and identity_equal(metadata(os.fstat(fd),target),rows['.']),'Target replaced/mounted')
        erase(fd,'.',0)
    finally:os.close(fd)
    require(identity_equal(metadata(os.stat(name,dir_fd=parent,follow_symlinks=False),target),rows['.']),'Target replaced before final rmdir')
    os.rmdir(name,dir_fd=parent);log('.',rows['.'],'cache_root')

def execute(args):
    # This must fail before a source lock or filesystem mutation without actual GO.
    auth_ref,helper_ref=authorization(args)
    require(os.geteuid()==os.getegid()==1000,'Exact ordinary source owner UID/GID1000 required')
    audit,summary,attempts,owner_ref=authenticated_inputs()
    require(tuple(Path(a[0]['cache_census']['root']['path']) for a in attempts)==TARGETS,'Literal target set changed')
    require(not OUTPUT.exists() and not OUTPUT.is_symlink(),'Fresh pruning output must be absent')
    source_fd=opened_directory(SOURCE);parents=[];removed=[];record=None;output_created=False
    try:
        fcntl.flock(source_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        no_mounted_targets(Path('/proc/self/mountinfo').read_text(),TARGETS)
        before=protected_snapshot(summary,attempts)
        live=no_competing_writer()
        inspections=fresh_stop_proofs(audit,attempts)
        plans=[]
        for attempt,_,_ in attempts:
            target=Path(attempt['cache_census']['root']['path'])
            parent=opened_directory(target.parent);parents.append(parent)
            require(sorted(os.listdir(parent))==[target.name],'Unpacked sibling inventory changed')
            fd=os.open(target.name,DIRECTORY_FLAGS,dir_fd=parent)
            try:rows=fd_census(fd,target,attempt['cache_census']['entries'],mount_id(parent))
            finally:os.close(fd)
            plans.append((parent,target,rows))
        compare_protected(before,protected_snapshot(summary,attempts))
        record={'schema':1,'kind':'phase1_exact_three_failed_vendor_cache_pruning_receipt_v1',
                'started_epoch_ns':time.time_ns(),'authorization':auth_ref,'helper':helper_ref,
                'audit_owner':owner_ref,'targets':list(map(str,TARGETS)),
                'protected_before':before,'fresh_original_profile_stop_proofs':inspections,
                'initial_running_container_writer_census':live,'source_exclusive_advisory_lock':True,
                'source_available_bytes_before':os.statvfs(SOURCE).f_bavail*os.statvfs(SOURCE).f_frsize,
                'discarded_scope':'interrupted extraction bytes; exact partial crash state not reconstructed',
                'trusted_no_old_restart_or_competing_writer_policy_required':True,
                'archive_bytes_hashed':False,'container_mutated':False,'build_or_runtime_qualification':False}
        os.mkdir(OUTPUT,0o700);output_created=True
        parent=opened_directory(OUTPUT.parent)
        try:os.fsync(parent)
        finally:os.close(parent)
        write_new(OUTPUT/'intent.json',record)
        with (OUTPUT/'removed-entries.jsonl').open('x',encoding='utf-8') as journal:
            journal.flush();os.fsync(journal.fileno())
            parent=opened_directory(OUTPUT)
            try:os.fsync(parent)
            finally:os.close(parent)
            for parent,target,rows in plans:
                no_competing_writer()
                # Reprove all exact old containers, not just cached successful observations.
                inspections=fresh_stop_proofs(audit,attempts)
                fd=os.open(target.name,DIRECTORY_FLAGS,dir_fd=parent)
                try:fd_census(fd,target,list(rows.values()),mount_id(parent))
                finally:os.close(fd)
                remove_exact(parent,target.name,target,rows,journal,removed)
                os.fsync(parent)
        after=protected_snapshot(summary,attempts);compare_protected(before,after)
        record.update(status='pruned_only_exact_three_interrupted_extraction_caches',protected_after=after,
                      final_original_profile_stop_proofs=fresh_stop_proofs(audit,attempts),
                      actual_targets_absent=all(not path.exists() and not path.is_symlink() for path in TARGETS))
        require(record['actual_targets_absent'],'Selected cache target survived')
    except BaseException as error:
        if record is not None and output_created:
            record.update(status='failed_partial_pruning' if removed else 'failed_before_cache_removal',
                          exception_class=type(error).__name__,exception=str(error))
            try:
                after=protected_snapshot(summary,attempts);compare_protected(before,after)
                record['protected_after_failure']=after
            except BaseException as diagnostic:
                record['protected_after_failure_error']={'class':type(diagnostic).__name__,'message':str(diagnostic)}
        raise
    finally:
        primary_pending=sys.exc_info()[0] is not None
        sealing_error=None
        if record is not None and output_created:
            record['completed_epoch_ns']=time.time_ns();record['removed_entries']=removed
            record['source_available_bytes_after']=os.statvfs(SOURCE).f_bavail*os.statvfs(SOURCE).f_frsize
            record['source_available_delta_bytes']=record['source_available_bytes_after']-record['source_available_bytes_before']
            record['unshared_extent_estimate_is_not_actual_space_delta']=True
            try:
                raw,ref=read_regular(OUTPUT/'removed-entries.jsonl')
                record['removed_entries_journal']=ref
            except BaseException as diagnostic:
                record['removed_entries_journal_error']={'class':type(diagnostic).__name__,'message':str(diagnostic)}
            try:write_new(OUTPUT/'pruning-receipt.json',record)
            except BaseException as sealing:
                # Never hide the primary pruning failure if the evidence volume
                # itself refuses the new receipt. Intent/journal stay untouched.
                print(json.dumps({'receipt_sealing_error':str(sealing),'partial_record':record},sort_keys=True),file=sys.stderr)
                sealing_error=sealing
        for fd in parents:os.close(fd)
        os.close(source_fd)
        if sealing_error is not None and not primary_pending:raise sealing_error

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-after-explicit-cache-exception-and-root-review',action='store_true')
    parser.add_argument('--reviewed-helper-sha256')
    parser.add_argument('--authorization-sha256')
    execute(parser.parse_args())

if __name__=='__main__':main()
