#!/usr/bin/python3
"""Bounded READ-ONLY G6--G9 work-cache census; no archive/image byte reads."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import time
import argparse

BASE = Path('/u/elric/tree/wonad-phase1-build-evidence')
SOURCE = Path('/u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1')
ARCHIVE = 'frankel-cp3a.261005.005-factory-3721e6ac.zip'
FACTORY_SHA = '3721e6accc2e87d851ee7966d794318078ec74c7cc32343daa10968264d6bb62'
CACHE_SHA = '458273099a83f97c60ed6ba1a7a40e14704f850b04068443946ca65e78dbe6c3'
PREFLIGHT_SHA = {
    6: 'bd4f2bb92f6f911099bfd20839aeb305da146b1773994e3b357bec46738a9e6c',
    7: '137fee3baeb58bf22c4a4f14bfcb377b599885dd0252fc64fc4cf272be578610',
    8: '5448176b9b7f81babfb6bdd8bc1b8b556ac6b13c6ec30e86741c9f9e4d6d13c5',
    9: 'adb22f5005ee5940023778f7b59518b046468e22a2df9f77e599795b2eba1605',
}

def require(ok, text):
    if not ok:
        raise RuntimeError(text)

def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate JSON key')
        value[key] = item
    return value

def meta(path):
    s = os.lstat(path)
    return {'path': str(path), 'device': s.st_dev, 'inode': s.st_ino,
            'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode),
            'file_type': stat.S_IFMT(s.st_mode), 'nlink': s.st_nlink,
            'bytes': s.st_size, 'allocated_bytes': s.st_blocks * 512,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns}

def small(path, expected=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 16*1024*1024,
                'not bounded regular evidence: ' + str(path))
        raw = b''
        while len(raw) < before.st_size:
            chunk = os.read(fd, min(65536, before.st_size-len(raw)))
            require(bool(chunk), 'short read')
            raw += chunk
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                       after.st_mtime_ns, after.st_ctime_ns), 'evidence changed')
    finally:
        os.close(fd)
    digest = hashlib.sha256(raw).hexdigest()
    require(expected is None or digest == expected, 'evidence hash mismatch')
    return raw, dict(meta(path), sha256=digest)

def load(path, expected=None):
    raw, reference = small(path, expected)
    return json.loads(raw, object_pairs_hook=unique), reference

def match_identity(path, expected):
    observed = meta(path)
    require(all(observed[k] == expected[k] for k in
                ('path','device','inode','uid','gid','mode')), 'directory/lock identity mismatch')
    return observed

def fiemap(path):
    """Read mapping metadata only, without FIEMAP_FLAG_SYNC or data reads."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, 'non-single-link file')
        start = 0
        extents = []
        while True:
            buffer = bytearray(32 + 56*256)
            struct.pack_into('<QQIIII', buffer, 0, start, (1<<64)-1-start, 0, 0, 256, 0)
            fcntl.ioctl(fd, 0xC020660B, buffer, True)
            count = struct.unpack_from('<QQIIII', buffer)[3]
            require(count <= 256, 'bad FIEMAP extent count')
            batch = [struct.unpack_from('<QQQQQIIII', buffer, 32+56*i) for i in range(count)]
            for e in batch:
                require(e[2] > 0 and e[0] >= start and e[3:5] == (0, 0) and e[6:] == (0, 0, 0),
                        'bad FIEMAP extent')
                extents.append({'logical': e[0], 'physical': e[1], 'bytes': e[2], 'flags': e[5]})
            require(len(extents) <= 8192, 'too many extents')
            if not batch or batch[-1][5] & 1:
                break
            end = batch[-1][0] + batch[-1][2]
            require(end > start, 'FIEMAP no progress')
            start = end
        after = os.fstat(fd)
        require((s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_blocks) ==
                (after.st_size,after.st_mtime_ns,after.st_ctime_ns,after.st_blocks), 'file changed')
        # LAST, UNWRITTEN, MERGED are harmless to allocation; exclude SHARED and
        # UNKNOWN/DELALLOC/ENCODED/ENCRYPTED/NOT_ALIGNED/INLINE/TAIL from exclusive estimate.
        uncertain = 0x2 | 0x4 | 0x8 | 0x80 | 0x100 | 0x200 | 0x400
        exclusive = sum(e['bytes'] for e in extents if not e['flags'] & (0x2000 | uncertain))
        shared = sum(e['bytes'] for e in extents if e['flags'] & 0x2000)
        return {'extent_count': len(extents), 'extent_flags': sorted({e['flags'] for e in extents}),
                'mapped_bytes': sum(e['bytes'] for e in extents), 'shared_extent_bytes': shared,
                'observed_unshared_extent_bytes': exclusive, 'extents': extents}
    finally:
        os.close(fd)

def tree(path):
    require(path.name == 'frankel-CP3A.261005.005-tmp' and path.parent.name == 'unpacked', 'wrong cache')
    root = meta(path)
    rows, stack, seen = [], [(path, 0)], set()
    while stack:
        current, depth = stack.pop()
        require(depth <= 20 and len(rows) < 10000, 'census bound exceeded')
        m = meta(current)
        require(m['device'] == root['device'] and (m['device'],m['inode']) not in seen,
                'mount/inode alias')
        seen.add((m['device'],m['inode']))
        if m['file_type'] == stat.S_IFDIR:
            for e in sorted(os.scandir(current), key=lambda e: e.name, reverse=True):
                stack.append((Path(e.path),depth+1))
        elif m['file_type'] == stat.S_IFREG:
            m['fiemap'] = fiemap(current)
        elif m['file_type'] == stat.S_IFLNK:
            m['opaque_symlink_target'] = os.readlink(current)
        else:
            raise RuntimeError('unexpected special cache entry')
        m['relative_path'] = str(current.relative_to(path))
        rows.append(m)
    rows.sort(key=lambda m:m['relative_path'])
    regular = [m for m in rows if m['file_type'] == stat.S_IFREG]
    return {'root':root, 'entries':rows, 'entry_count':len(rows), 'regular_count':len(regular),
            'logical_regular_bytes':sum(m['bytes'] for m in regular),
            'allocated_regular_bytes':sum(m['allocated_bytes'] for m in regular),
            'observed_unshared_extent_bytes':sum(m['fiemap']['observed_unshared_extent_bytes'] for m in regular),
            'shared_extent_bytes':sum(m['fiemap']['shared_extent_bytes'] for m in regular),
            'directory_and_symlink_allocated_bytes':sum(m['allocated_bytes'] for m in rows if m['file_type'] != stat.S_IFREG)}

def inspect_old(preflight, result):
    identity = result['container']['id']
    argv = ['/usr/bin/docker','--host','unix:///var/run/docker.sock','inspect','--type','container',identity]
    run = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20, check=False,
                         env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','HOME':'/u/elric'})
    require(run.returncode == 0 and not run.stderr and len(run.stdout) < 65536, 'inspect failed')
    values = json.loads(run.stdout, object_pairs_hook=unique)
    require(isinstance(values,list) and len(values)==1, 'inspect ambiguous')
    info = values[0]; cfg, host, state = info['Config'],info['HostConfig'],info['State']
    create = preflight['create_argv']; image = preflight['docker_authority']['builder_image']
    require(create.count(image)==1, 'image argv ambiguous')
    command = create[create.index(image)+1:]
    def option(key):
        require(create.count(key)==1,'option ambiguous: '+key)
        return create[create.index(key)+1]
    require(info['Id']==identity and info['Name']=='/'+result['container']['name'] and info['Image']==image,
            'container identity mismatch')
    require(cfg['Image']==image and cfg['Cmd']==command and cfg['Entrypoint']==['/usr/bin/env'] and
            cfg['User']=='1000:1000' and cfg['WorkingDir']=='/grapheneos' and
            cfg['Labels']=={'org.wonad.phase1.vendor-attempt':result['container']['nonce'],
                            'org.wonad.phase1.vendor-mode':'prepare'} and
            info['Path']=='/usr/bin/env' and info['Args']==command, 'config differs')
    expected = {'Memory':int(option('--memory')),'MemorySwap':int(option('--memory-swap')),
                'NanoCpus':4_000_000_000,'CpusetCpus':'0-3','PidsLimit':2048,'ReadonlyRootfs':True,
                'NetworkMode':'bridge','Privileged':False,'AutoRemove':False,
                'RestartPolicy':{'Name':'no','MaximumRetryCount':0},
                'Tmpfs':{'/tmp':option('--tmpfs').split(':',1)[1]},'CapDrop':['ALL'],
                'SecurityOpt':['label=disable','no-new-privileges=true']}
    require(all(host.get(k)==v for k,v in expected.items()), 'original HostConfig differs')
    binds = [create[i+1] for i,v in enumerate(create) if v=='--volume']
    require(len(binds)==3 and sorted(host['Binds'])==sorted(binds), 'original binds differ')
    mounts = {m['Destination']:m for m in info['Mounts']}
    require(len(info['Mounts'])==len(mounts)==3, 'mount count differs')
    for bind in binds:
        source,dest,mode=bind.rsplit(':',2)
        require(mounts[dest]=={'Type':'bind','Source':source,'Destination':dest,'Mode':mode,
                              'RW':mode=='rw','Propagation':'rprivate'}, 'mount differs')
    for key in ('CapAdd','Devices','DeviceRequests','DeviceCgroupRules','GroupAdd','PortBindings',
                'VolumesFrom','Links','ExtraHosts'):
        require(host.get(key) in (None,[],{}),'extra authority: '+key)
    require(host['PidMode']==host['UTSMode']==host['UsernsMode']=='' and host['IpcMode']=='private' and
            not cfg.get('ExposedPorts') and not cfg.get('Volumes') and not cfg['AttachStdin'] and
            cfg['AttachStdout'] and cfg['AttachStderr'] and not cfg['OpenStdin'] and
            not cfg['StdinOnce'] and not cfg['Tty'], 'namespace/stdio differs')
    require(state['Status']=='exited' and state['Running'] is False and state['Paused'] is False and
            state['Restarting'] is False and state['Dead'] is False and type(state['Pid']) is int and
            state['Pid']==0 and type(state['OOMKilled']) is bool and type(state['ExitCode']) is int,
            'not stopped')
    return {'argv':argv,'returncode':run.returncode,'stdout':run.stdout.decode(),
            'stdout_sha256':hashlib.sha256(run.stdout).hexdigest(),'stderr':'',
            'original_profile_matches':True,'state':state,'profile':expected}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', type=int, choices=range(6,10))
    parser.add_argument('--summary', action='store_true')
    args = parser.parse_args()
    require(not (args.generation and args.summary), 'choose one output projection')
    started = time.time_ns()
    cache, cache_ref = load(BASE/'phase1-frankel-factory-cache-20261011-1/receipt.json', CACHE_SHA)
    attempts=[]
    all_unshared=[]
    source_pins={}
    for generation in range(6,10):
        prefix = BASE/f'phase1-frankel-baseline-vendor-cache-20261012-{generation}'
        preflight,pref_ref=load(Path(str(prefix)+'.preflight.json'),PREFLIGHT_SHA[generation])
        result,res_ref=load(Path(str(prefix)+'.result.json'))
        lock,lock_ref=load(Path(str(prefix)+'.lock.json'),result['inputs']['attempt_lock']['initial']['sha256'])
        _,log_ref=small(Path(str(prefix)+'.log'))
        require(result['source']==str(SOURCE) and preflight['source']==str(SOURCE), 'source differs')
        require(result['work']==preflight['reflink_workspace'], 'work joins differ')
        work=Path(result['work']['directory']['path'])
        require(work==BASE/f'phase1-frankel-vendor-cache-work-20261012-{generation-1}', 'wrong work')
        work_meta=match_identity(work,result['work']['directory'])
        require(sorted(e.name for e in os.scandir(work))==[ARCHIVE,'unpacked'],'unexpected work root')
        lock_meta=match_identity(lock_ref['path'],result['inputs']['attempt_lock']['initial'])
        archive=meta(work/ARCHIVE)
        require(archive['bytes']==11378664978 and archive['uid']==archive['gid']==1000 and
                archive['mode']==0o444 and archive['nlink']==1 and
                result['work']['archive']['sha256_from_authenticated_receipt']==FACTORY_SHA,
                'archive metadata differs')
        unpacked=meta(work/'unpacked')
        require(sorted(e.name for e in os.scandir(work/'unpacked'))==['frankel-CP3A.261005.005-tmp'],
                'unexpected unpacked root')
        census=tree(work/'unpacked/frankel-CP3A.261005.005-tmp')
        for row in census['entries']:
            for e in row.get('fiemap',{}).get('extents',[]):
                if not e['flags'] & (0x2000|0x2|0x4|0x8|0x80|0x100|0x200|0x400):
                    all_unshared.append((e['physical'],e['physical']+e['bytes']))
        current_sources={}
        for relative,reference in preflight['first_source']['source_inputs'].items():
            _,current=small(SOURCE/relative,reference['sha256']);current_sources[relative]=current
            require(relative not in source_pins or source_pins[relative]['sha256']==current['sha256'],
                    'historical source joins differ')
            source_pins[relative]=current
        attempts.append({'generation':generation,'references':{'preflight':pref_ref,'result':res_ref,
                         'lock':lock_ref,'log':log_ref},'historic_result_status':result['status'],
                         'work':work_meta,'lock_identity':lock_meta,'archive_preserved':archive,
                         'archive_fiemap_metadata_only':fiemap(work/ARCHIVE),
                         'unpacked_directory_preserved':unpacked,'cache_census':census,
                         'container':inspect_old(preflight,result),'source_inputs_current_match':True})
    intervals=sorted(all_unshared)
    require(all(left[1]<=right[0] for left,right in zip(intervals,intervals[1:])),
            'unshared physical ranges overlap')
    physical_ledger_sha = hashlib.sha256(json.dumps(intervals,separators=(',',':')).encode()).hexdigest()
    # Retain exact mapping hashes/counts/flags/byte totals rather than emitting
    # thousands of physical extents. Replay is this same metadata-only ioctl.
    for attempt in attempts:
        mappings = [attempt['archive_fiemap_metadata_only']] + [
            row['fiemap'] for row in attempt['cache_census']['entries'] if 'fiemap' in row]
        for mapping in mappings:
            ledger = mapping.pop('extents')
            mapping['extent_ledger_sha256'] = hashlib.sha256(
                json.dumps(ledger,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    output={'schema':1,'kind':'phase1_failed_vendor_work_readonly_cache_observation_v1',
            'started_epoch_ns':started,'finished_epoch_ns':time.time_ns(),'attempts':attempts,
            'factory_cache_receipt':cache_ref,'current_source_inputs':source_pins,
            'observed_unshared_cache_extent_bytes':sum(a['cache_census']['observed_unshared_extent_bytes'] for a in attempts),
            'allocated_cache_regular_bytes':sum(a['cache_census']['allocated_regular_bytes'] for a in attempts),
            'shared_cache_extent_bytes':sum(a['cache_census']['shared_extent_bytes'] for a in attempts),
            'cache_physical_unshared_intervals_pairwise_disjoint':True,
            'cache_physical_unshared_interval_ledger_sha256':physical_ledger_sha,
            'source_filesystem_available_bytes':os.statvfs(SOURCE).f_bavail*os.statvfs(SOURCE).f_frsize,
            'negative_claims':{'cleanup_authorized':False,'deleted':False,'archive_bytes_hashed':False,
              'partition_bytes_hashed':False,'full_source_walk':False,'build_or_container_mutation':False,
              'exclusive_lock_held':False,'hostile_admin_exclusion':False,'reserved_future_reclaim':False}}
    if args.generation:
        output = {'schema':1,'kind':'phase1_failed_vendor_work_readonly_attempt_observation_v1',
                  'started_epoch_ns':started,'finished_epoch_ns':time.time_ns(),
                  'attempt':next(a for a in attempts if a['generation']==args.generation),
                  'negative_claims':output['negative_claims']}
    elif args.summary:
        for attempt in output['attempts']:
            attempt['cache_census'].pop('entries')
            attempt['container'].pop('stdout')
    print(json.dumps(output,sort_keys=True,separators=(',',':')))

if __name__=='__main__':
    main()
