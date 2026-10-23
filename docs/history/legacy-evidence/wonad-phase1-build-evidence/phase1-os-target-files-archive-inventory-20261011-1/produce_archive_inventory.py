#!/usr/bin/env python3
"""Observe exact receipted ZIP bytes. No extraction/package/signature claims.

Run through run_snapshot.py, which authenticates and executes one captured
source snapshot. Tests may call these functions only with synthetic fixtures.
"""
from __future__ import annotations
import argparse
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import zipfile
import zlib

POLICY = dict(archive_bytes=128*1024**3, entries=250000,
              central_bytes=128*1024**2, member_bytes=64*1024**3,
              total_bytes=128*1024**3, name_bytes=4096,
              symlink_bytes=65536, ledger_bytes=256*1024**2,
              json_bytes=4*1024**2, chunk_bytes=1024**2)
PAIR_KEYS = {'schema','kind','target','predecessor','successor','incremental_ota',
             'official_delta_generator','receipt_generator','pair_verifier'}
FULL_KEYS = {'schema','kind','build','target','source','grapheneos_lock','wonad_stage',
             'updater_stage','apk_signer_sha256','artifacts','phase1_provenance',
             'files','generator','artifact_verifier'}
END_KEYS = {'number','receipt','build','target','source','grapheneos_lock','wonad_stage',
            'updater_stage','phase1_provenance','apk_signer_sha256'}
TARGET = dict(device='Pixel 10', product='frankel', abi='arm64-v8a', variant='user',
              lunch_target='frankel-cur-user')
CLAIMS = dict(release_gate_closed=False, cryptography_performed=False,
              package_identity_derived=False, extraction_performed=False,
              runtime_qualified=False)

class InventoryError(ValueError): pass

def need(condition, message):
    if not condition: raise InventoryError(message)

def exact(value, keys, label):
    need(type(value) is dict and set(value) == set(keys), 'Unexpected '+label+' fields')

def identical(a,b):
    if type(a) is not type(b): return False
    if type(a) is dict: return set(a)==set(b) and all(identical(a[k],b[k]) for k in a)
    if type(a) is list: return len(a)==len(b) and all(identical(x,y) for x,y in zip(a,b))
    return a==b

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result

def decode(data):
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(InventoryError('Nonfinite JSON')))
    except (UnicodeError, json.JSONDecodeError) as e:
        raise InventoryError('Invalid JSON') from e

def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False)+'\n').encode()

def reference(data): return {'sha256':hashlib.sha256(data).hexdigest(), 'size':len(data)}

def hash_shape(row):
    exact(row, {'sha256','size'}, 'file reference')
    need(type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']) and
         type(row['size']) is int and row['size'] > 0, 'Invalid file reference')

def ordinary_fd(path):
    """Reject every symlink path component; FIFO opens cannot block."""
    path = Path(path)
    need(path.is_absolute() and str(path) == os.path.normpath(str(path)), 'Absolute canonical path required')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), 'Not a regular file')
        except BaseException:
            os.close(fd)
            raise
        return fd
    finally: os.close(directory)

def identity(fd):
    s = os.fstat(fd)
    return dict(device=s.st_dev, inode=s.st_ino, mode=s.st_mode, size=s.st_size,
                mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns)

def fd_digest(fd, limit):
    before = identity(fd)
    need(0 < before['size'] <= limit, 'File size outside bound')
    h = hashlib.sha256()
    offset = 0
    while offset < before['size']:
        data = os.pread(fd, min(POLICY['chunk_bytes'], before['size']-offset), offset)
        need(data, 'Truncated ordinary file')
        h.update(data); offset += len(data)
    need(identity(fd) == before and not os.pread(fd, 1, offset), 'File changed during hashing')
    return dict(sha256=h.hexdigest(), size=offset)

def snapshot(path, expected):
    hash_shape(expected)
    fd = ordinary_fd(path)
    try:
        need(fd_digest(fd, POLICY['json_bytes']) == expected, 'Authenticated JSON digest mismatch')
        data = os.pread(fd, expected['size']+1, 0)
        need(reference(data) == expected, 'JSON snapshot changed')
        return decode(data), data
    finally: os.close(fd)

def select_pair(path, expected_sha):
    need(type(expected_sha) is str and re.fullmatch('[0-9a-f]{64}', expected_sha), 'Invalid pair digest')
    path = Path(path)
    fd = ordinary_fd(path)
    try:
        ref = fd_digest(fd, POLICY['json_bytes'])
        need(ref['sha256'] == expected_sha, 'Pair authentication failed')
        raw = os.pread(fd, ref['size']+1, 0)
        need(reference(raw) == ref, 'Pair snapshot changed')
    finally: os.close(fd)
    pair = decode(raw)
    exact(pair, PAIR_KEYS, 'pair')
    need(type(pair['schema']) is int and pair['schema'] == 1 and
         pair['kind'] == 'wonad-grapheneos-incremental-pair' and pair['target'] == 'frankel', 'Wrong pair scope')
    selected = {}
    for role in ('predecessor','successor'):
        endpoint = pair[role]
        exact(endpoint, END_KEYS, 'endpoint')
        number = endpoint['number']
        need(type(number) is str and re.fullmatch('[0-9]{10}', number), 'Invalid build number')
        relative = f'{number}/release-frankel-{number}/release-receipt.json'
        exact(endpoint['receipt'], {'path','sha256','size'}, 'endpoint reference')
        need(endpoint['receipt']['path'] == relative, 'Endpoint path relabelled')
        full_ref = {k:endpoint['receipt'][k] for k in ('sha256','size')}
        full_path = path.parent.parent / relative
        full, full_raw = snapshot(full_path, full_ref)
        exact(full, FULL_KEYS, 'full receipt')
        need(type(full['schema']) is int and full['schema'] == 4 and
             full['kind'] == 'wonad-grapheneos-release' and full['target'] == TARGET, 'Wrong full receipt scope')
        exact(full['build'], {'number','post_build','timestamp','datetime_utc'}, 'build')
        need(full['build']['number'] == number and type(full['build']['timestamp']) is int and
             full['build']['timestamp'] > 0 and type(full['build']['post_build']) is str and
             full['build']['post_build'], 'Invalid build identity')
        bound = {'number':number, 'receipt':endpoint['receipt']}
        for field in END_KEYS-{'number','receipt'}: bound[field] = full[field]
        need(identical(bound,endpoint), 'Full endpoint identity mismatch')
        need(type(full['apk_signer_sha256']) is str and
             re.fullmatch('[0-9a-f]{64}', full['apk_signer_sha256']) and
             type(full['updater_stage']) is dict and
             type(full['updater_stage'].get('update_url')) is str and
             full['updater_stage']['update_url'], 'Missing receipted signer/channel')
        for field in ('source','grapheneos_lock','wonad_stage','phase1_provenance'):
            need(type(full[field]) is dict and full[field], 'Empty endpoint identity')
        need(type(full['artifacts']) is dict and
             full['artifacts'].get('signed_target_files') == 'frankel-target_files.zip' and
             type(full['files']) is dict, 'Wrong selected artifact role')
        archive_ref = full['files'].get('frankel-target_files.zip')
        hash_shape(archive_ref)
        selected[role] = dict(endpoint=endpoint, full_path=full_path, full_raw=full_raw,
                              full_ref=full_ref, archive_path=full_path.parent/'frankel-target_files.zip',
                              archive_ref=archive_ref)
    before, after = (selected[r]['endpoint'] for r in ('predecessor','successor'))
    need(int(after['number']) > int(before['number']) and
         after['build']['timestamp'] > before['build']['timestamp'], 'OTA successor must be strictly newer')
    need(before['apk_signer_sha256'] == after['apk_signer_sha256'] and
         before['updater_stage']['update_url'] == after['updater_stage']['update_url'], 'Receipted lineage changed')
    need(path.parent.name == after['number'] and path.parent.parent.name == 'releases' and
         path.name == f"frankel-incremental-{before['number']}-{after['number']}-receipt.json", 'Noncanonical pair layout')
    return pair, raw, ref, selected

def take(fd, offset, size):
    need(offset >= 0 and size >= 0, 'Negative ZIP range')
    data = os.pread(fd, size, offset)
    need(len(data) == size, 'Truncated ZIP structure')
    return data

def extras(data):
    values = {}; p = 0
    while p < len(data):
        need(p+4 <= len(data), 'Truncated extra field')
        tag, n = struct.unpack_from('<HH', data, p); p += 4
        need(p+n <= len(data) and tag not in values, 'Malformed/duplicate extra field')
        values[tag] = data[p:p+n]; p += n
    return values

def zip64_values(fields, extra):
    """Only sentinel fields consume ZIP64 values, in specification order."""
    parsed = extras(extra); z = parsed.get(1, b''); p = 0; result=[]
    for value, sentinel, width in fields:
        if value == sentinel:
            need(p+width <= len(z), 'Missing needed Zip64 field')
            value = int.from_bytes(z[p:p+width], 'little'); p += width
        result.append(value)
    if 1 in parsed: need(p == len(z), 'Unexpected Zip64 extra data')
    return result

def central_directory(fd, policy=POLICY):
    size = os.fstat(fd).st_size
    need(22 <= size <= policy['archive_bytes'], 'Archive size outside bound')
    tail_start = max(0, size-65557)
    tail = take(fd, tail_start, size-tail_start)
    candidates=[]
    for p in range(len(tail)-22, -1, -1):
        if tail[p:p+4] == b'PK\x05\x06':
            row=struct.unpack_from('<4s4H2IH', tail, p)
            if p+22+row[-1] == len(tail): candidates.append((tail_start+p,row))
    need(len(candidates) == 1, 'Missing/ambiguous terminal EOCD')
    end, row=candidates[0]
    _, disk, cd_disk, count_disk, count, cd_size, cd_offset, comment=row
    need(disk == cd_disk == 0 and count_disk == count, 'Multidisk ZIP')
    has_locator = end >= 20 and take(fd,end-20,4) == b'PK\x06\x07'
    is64 = has_locator or count == 65535 or cd_size == 0xffffffff or cd_offset == 0xffffffff
    cd_end = end
    if is64:
        need(has_locator, 'Missing Zip64 locator')
        _, locator_disk, record_offset, disks = struct.unpack('<4sIQI',take(fd,end-20,20))
        need(locator_disk == 0 and disks == 1, 'Multidisk Zip64')
        z=struct.unpack('<4sQ2H2I4Q',take(fd,record_offset,56))
        need(z[0] == b'PK\x06\x06' and 44 <= z[1] <= 1024**2 and
             record_offset+12+z[1] == end-20 and z[4] == z[5] == 0 and z[6] == z[7], 'Invalid Zip64 EOCD')
        for short, long, sentinel in ((count,z[7],65535),(cd_size,z[8],0xffffffff),(cd_offset,z[9],0xffffffff)):
            need(short == sentinel or short == long, 'Conflicting Zip64 EOCD')
        count,cd_size,cd_offset=z[7:10]; cd_end=record_offset
    need(1 <= count <= policy['entries'] and 46 <= cd_size <= policy['central_bytes'] and
         0 <= cd_offset < cd_end and cd_offset+cd_size == cd_end, 'Unbounded/noncanonical central directory')
    rows=[]; p=cd_offset
    while p < cd_end:
        need(len(rows) < count and len(rows) < policy['entries'], 'Central count mismatch')
        row=struct.unpack('<4s6H3I5H2I',take(fd,p,46))
        need(row[0] == b'PK\x01\x02', 'Bad central signature')
        name_size,extra_size,comment_size=row[10:13]
        need(0 < name_size <= policy['name_bytes'] and p+46+name_size+extra_size+comment_size <= cd_end,
             'Central member length outside bound')
        body=take(fd,p+46,name_size+extra_size+comment_size)
        name=body[:name_size]; extra=body[name_size:name_size+extra_size]
        usize,csize,offset,member_disk=zip64_values(
            [(row[9],0xffffffff,8),(row[8],0xffffffff,8),(row[16],0xffffffff,8),(row[13],65535,4)],extra)
        need(member_disk == 0, 'Multidisk member')
        rows.append(dict(name_bytes=name, extra=extra, flags=row[3],method=row[4],crc=row[7],
                         usize=usize,csize=csize,offset=offset,creator=row[1]>>8,external=row[15]))
        p += 46+len(body)
    need(p == cd_end and len(rows) == count, 'Exact central count mismatch')
    return rows,dict(zip64=is64,entry_count=count,central_directory_offset=cd_offset,
                     central_directory_bytes=cd_size,central_directory_sha256=hashlib.sha256(take(fd,cd_offset,cd_size)).hexdigest(),
                     eocd_offset=end,comment_bytes=comment)

def canonical(raw, flags, directory):
    try: name=raw.decode('utf-8' if flags & 2048 else 'cp437')
    except UnicodeError as e: raise InventoryError('Undecodable ZIP member') from e
    need(name and '\\' not in name and not any(ord(c)<32 or 127<=ord(c)<=159 for c in name), 'Unsafe member name')
    member=name[:-1] if directory else name
    need(member and not member.startswith('/') and
         all(x not in ('','.','..') for x in member.split('/')) and
         (not name.endswith('/') or directory), 'Noncanonical member path')
    return name,member

def physical(fd,row,central):
    p=row['offset']; need(0 <= p < central, 'Invalid local header offset')
    local=struct.unpack('<4s5H3I2H',take(fd,p,30))
    need(local[0] == b'PK\x03\x04' and local[2] == row['flags'] and local[3] == row['method'], 'Local method/flag mismatch')
    body=take(fd,p+30,local[9]+local[10])
    need(body[:local[9]] == row['name_bytes'], 'Local name mismatch')
    local_u,local_c=zip64_values([(local[8],0xffffffff,8),(local[7],0xffffffff,8)],body[local[9]:])
    start=p+30+len(body); end=start+row['csize']
    need(end <= central, 'Member crosses central directory')
    if row['flags'] & 8:
        need(local[6] in (0,row['crc']) and local_u in (0,row['usize']) and local_c in (0,row['csize']), 'Local descriptor fields conflict')
        width=8 if local[7] == 0xffffffff or local[8] == 0xffffffff or row['usize'] > 0xffffffff or row['csize'] > 0xffffffff else 4
        descriptor_end=end
        has_signature=take(fd,end,4) == b'PK\x07\x08'
        if has_signature: descriptor_end += 4
        data=take(fd,descriptor_end,4+2*width)
        crc=int.from_bytes(data[:4],'little'); csize=int.from_bytes(data[4:4+width],'little'); usize=int.from_bytes(data[4+width:],'little')
        need((crc,csize,usize) == (row['crc'],row['csize'],row['usize']), 'Invalid data descriptor')
        end=descriptor_end+len(data)
        need(end <= central, 'Descriptor crosses central directory')
    else:
        need((local[6],local_c,local_u) == (row['crc'],row['csize'],row['usize']), 'Local size/CRC mismatch')
    return start,end

def payload_chunks(fd,start,row,chunk):
    """Measure true expansion; ZipExtFile alone truncates to declared usize."""
    if row['method'] == 0:
        need(row['csize'] == row['usize'], 'Stored size disagreement')
        offset=0
        while offset < row['csize']:
            b=take(fd,start+offset,min(chunk,row['csize']-offset)); offset += len(b); yield b
        return
    decoder=zlib.decompressobj(-15); offset=0; pending=b''
    while not decoder.eof:
        if not pending and offset < row['csize']:
            pending=take(fd,start+offset,min(chunk,row['csize']-offset)); offset += len(pending)
        had_input=bool(pending)
        b=decoder.decompress(pending,chunk); pending=decoder.unconsumed_tail
        if b: yield b
        need(not decoder.unused_data, 'Trailing compressed member data')
        if decoder.eof:
            need(offset == row['csize'] and not pending, 'Compressed data after stream end')
            break
        need(had_input or b, 'Truncated DEFLATE stream')
    need(decoder.eof and not decoder.unused_data and not pending, 'Truncated DEFLATE stream')

def observe_archive(path, expected, endpoint, policy=POLICY):
    hash_shape(expected)
    fd=ordinary_fd(path)
    try:
        before=identity(fd)
        need(fd_digest(fd,policy['archive_bytes']) == expected, 'Archive authentication failed')
        rows,structure=central_directory(fd,policy)
        observed=[]; raw_records=[]; seen={}; intervals=[]; total=0
        with os.fdopen(os.dup(fd),'rb') as stream, zipfile.ZipFile(stream,allowZip64=True) as archive:
            infos=archive.infolist()
            need(len(infos) == len(rows), 'Library central count disagreement')
            for index,(row,info) in enumerate(zip(rows,infos)):
                need(row['method'] in (0,8) and row['flags'] & ~(8|2048|2|4) == 0 and
                     (row['method'] == 8 or not row['flags'] & 6), 'Unsupported compression/flags')
                mode=(row['external']>>16)&0o170000 if row['creator'] == 3 else 0
                directory=row['name_bytes'].endswith(b'/')
                need(not row['external'] & 16 or directory, 'DOS directory flag conflict')
                need(mode in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK) and
                     (mode == 0 or (mode == stat.S_IFDIR) == directory), 'Unsupported/contradictory member type')
                kind='directory' if directory else 'symlink' if mode == stat.S_IFLNK else 'regular'
                name,member=canonical(row['name_bytes'],row['flags'],directory)
                need(member not in seen, 'Duplicate canonical member')
                seen[member]=kind
                need(info.orig_filename == info.filename == name and info.header_offset == row['offset'] and
                     info.file_size == row['usize'] and info.compress_size == row['csize'] and
                     info.CRC == row['crc'] and info.flag_bits == row['flags'] and info.compress_type == row['method'], 'Library member disagreement')
                need(row['usize'] <= policy['member_bytes'] and row['csize'] <= policy['archive_bytes'] and
                     (kind != 'symlink' or row['usize'] <= policy['symlink_bytes']) and
                     (kind != 'directory' or row['usize'] == 0), 'Expanded member outside bound')
                total += row['usize']; need(total <= policy['total_bytes'], 'Expanded total outside bound')
                start,end=physical(fd,row,structure['central_directory_offset']); intervals.append((row['offset'],end))
                h=hashlib.sha256(); crc=0; emitted=0
                for block in payload_chunks(fd,start,row,policy['chunk_bytes']):
                    emitted += len(block)
                    need(emitted <= row['usize'] and emitted <= policy['member_bytes'], 'Expanded stream exceeded bound')
                    h.update(block); crc=binascii.crc32(block,crc)
                need(emitted == row['usize'] and crc == row['crc'], 'Expanded size/CRC mismatch')
                result=dict(endpoint=endpoint, namespace='target-files',member=member,zip_name=name,
                            central_index=index,type=kind,creator_system=row['creator'],unix_mode=row['external']>>16,
                            external_attr=row['external'],flags=row['flags'],compression_method=row['method'],
                            compressed_size=row['csize'],expanded_size=emitted,crc32=f'{crc:08x}',sha256=h.hexdigest(),
                            local_header_offset=row['offset'],compressed_data_offset=start,raw_listing_index=index)
                observed.append(result)
                raw_records.append(dict(result, name_bytes_hex=row['name_bytes'].hex(),extra_sha256=hashlib.sha256(row['extra']).hexdigest()))
        previous=-1
        for start,end in sorted(intervals):
            need(start >= previous, 'Overlapping physical members'); previous=end
        for member in seen:
            parts=member.split('/')
            for length in range(1,len(parts)):
                need(seen.get('/'.join(parts[:length]),'directory') == 'directory', 'Non-directory member prefix')
        need(fd_digest(fd,policy['archive_bytes']) == expected and identity(fd) == before, 'Archive changed during observation')
        path_stat=os.stat(path,follow_symlinks=False)
        need((path_stat.st_dev,path_stat.st_ino)==(before['device'],before['inode']), 'Archive pathname replaced')
        structure.update(expanded_total=total,regular_count=sum(x['type']=='regular' for x in observed),
                         directory_count=sum(x['type']=='directory' for x in observed),symlink_count=sum(x['type']=='symlink' for x in observed))
        return sorted(observed,key=lambda x:x['member']),raw_records,structure,dict(before,before_hash=expected,after_hash=expected,path_still_names_fd=True)
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, struct.error, UnicodeError,zlib.error) as e:
        raise InventoryError('ZIP observation failed: '+str(e)) from e
    finally: os.close(fd)

def write_new(directory,name,data,limit):
    return write_sequence(directory,name,(data,),limit)

def write_sequence(directory,name,blocks,limit):
    """Stream bounded evidence; publish only complete bytes without overwrite."""
    path=directory/name
    need(not path.exists() and not path.is_symlink(),'Evidence already exists')
    fd,temporary=tempfile.mkstemp(prefix='.inventory-',dir=directory)
    digest=hashlib.sha256(); size=0
    try:
        with os.fdopen(fd,'wb') as output:
            for block in blocks:
                size+=len(block); need(size<=limit,'Evidence file exceeds bound')
                output.write(block); digest.update(block)
            output.flush(); os.fsync(output.fileno())
        os.link(temporary,path,follow_symlinks=False)
        directory_fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        return dict(path=name,sha256=digest.hexdigest(),size=size)
    finally: os.unlink(temporary)

def produce(pair_path,pair_sha,output,implementation):
    output=Path(output)
    need(output.is_absolute() and not output.exists() and not output.is_symlink(), 'Fresh absolute output required')
    # Authenticate every parent with no-follow directory traversal before mkdir.
    parent_fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in output.parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            os.close(parent_fd); parent_fd=next_fd
        os.mkdir(output.name,0o700,dir_fd=parent_fd)
    finally: os.close(parent_fd)
    try:
        pair,pair_raw,pair_ref,selected=select_pair(pair_path,pair_sha)
        pair_snapshot=write_new(output,'pair.json',pair_raw,POLICY['json_bytes'])
        endpoints={}
        for role in ('predecessor','successor'):
            entry=selected[role]
            full_snapshot=write_new(output,role+'-release.json',entry['full_raw'],POLICY['json_bytes'])
            members,raw,structure,fd_state=observe_archive(entry['archive_path'],entry['archive_ref'],role)
            structure['member_inventory']=write_sequence(output,role+'-members.jsonl',(encoded(r) for r in members),POLICY['ledger_bytes'])
            structure['raw_listing']=write_sequence(output,role+'-raw.jsonl',(encoded(r) for r in raw),POLICY['ledger_bytes'])
            endpoints[role]=dict(build={k:entry['endpoint']['build'][k] for k in ('number','timestamp','post_build')},
                release_receipt=dict(origin=entry['endpoint']['receipt']['path'],**entry['full_ref'],snapshot=full_snapshot),
                receipted_endpoint_identity=entry['endpoint'],archive=dict(role='signed_target_files',
                origin=entry['endpoint']['receipt']['path'].rsplit('/',1)[0]+'/frankel-target_files.zip',**entry['archive_ref']),
                fd_observation=fd_state,zip_structure=structure)
        # Re-select exact originals; retained authenticated JSON must still be current.
        again=select_pair(pair_path,pair_sha)
        need(again[1] == pair_raw and all(again[3][r]['full_raw']==selected[r]['full_raw'] for r in selected), 'Receipt inputs changed')
        for role,entry in selected.items():
            fd=ordinary_fd(entry['archive_path'])
            try:
                need(identical(identity(fd),{k:endpoints[role]['fd_observation'][k] for k in identity(fd)}) and
                     fd_digest(fd,POLICY['archive_bytes']) == entry['archive_ref'], 'Archive changed before publication')
            finally: os.close(fd)
        result=dict(schema=1,kind='phase1_authenticated_target_files_archive_inventory',status='observed',
            scope='authenticated_pair_selected_target_files_archive_observations',**CLAIMS,
            pair=dict(origin=str(pair_path),**pair_ref,snapshot=pair_snapshot),implementation=implementation,endpoints=endpoints)
        write_new(output,'receipt.json',encoded(result),POLICY['json_bytes'])
        directory_fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        return result
    except BaseException as e:
        if not (output/'failure.json').exists():
            write_new(output,'failure.json',encoded(dict(schema=1,status='failed',error_type=type(e).__name__,error=str(e),
                      release_gate_closed=False,partial_evidence_preserved=True)),POLICY['json_bytes'])
        raise

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pair-receipt',required=True,type=Path)
    parser.add_argument('--expected-pair-receipt-sha256',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args(argv)
    try:
        need('__authenticated_implementation__' in globals(), 'Use the authenticated run_snapshot.py launcher')
        implementation=dict(globals()['__authenticated_implementation__'],structural_policy=POLICY)
        result=produce(args.pair_receipt,args.expected_pair_receipt_sha256,args.output,implementation)
        print(json.dumps({'status':'observed','receipt':str(args.output/'receipt.json'),**CLAIMS},sort_keys=True))
        return 0
    except (InventoryError,OSError) as e:
        print('FAIL: '+str(e),file=sys.stderr); return 1

if __name__=='__main__': sys.exit(main())
