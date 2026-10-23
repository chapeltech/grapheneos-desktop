#!/usr/bin/env python3
"""Independent archive observation auditor. Never imports/calls producer."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile
import zlib

LIMITS={'archive_bytes':128*1024**3,'entries':250000,'central_bytes':128*1024**2,
        'member_bytes':64*1024**3,'total_bytes':128*1024**3,'name_bytes':4096,
        'symlink_bytes':65536,'ledger_bytes':256*1024**2,'json_bytes':4*1024**2,
        'chunk_bytes':1024**2}
FALSE_CLAIMS={'release_gate_closed','cryptography_performed','package_identity_derived',
              'extraction_performed','runtime_qualified'}
PAIR_FIELDS={'schema','kind','target','predecessor','successor','incremental_ota',
             'official_delta_generator','receipt_generator','pair_verifier'}
END_FIELDS={'number','receipt','build','target','source','grapheneos_lock','wonad_stage',
            'updater_stage','phase1_provenance','apk_signer_sha256'}
FULL_FIELDS={'schema','kind','build','target','source','grapheneos_lock','wonad_stage',
             'updater_stage','apk_signer_sha256','artifacts','phase1_provenance',
             'files','generator','artifact_verifier'}
DEVICE={'device':'Pixel 10','product':'frankel','abi':'arm64-v8a','variant':'user','lunch_target':'frankel-cur-user'}

class AuditError(ValueError): pass

def check(ok,message):
    if not ok: raise AuditError(message)

def fields(value,names):
    check(type(value) is dict and set(value)==set(names),'Unexpected object fields')

def json_object(pairs):
    value={}
    for k,v in pairs:
        check(k not in value,'Duplicate JSON key'); value[k]=v
    return value

def parse_json(data):
    try:
        return json.loads(data.decode('utf-8'),object_pairs_hook=json_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(AuditError('Nonfinite JSON')))
    except (UnicodeError,json.JSONDecodeError) as e: raise AuditError('Invalid JSON') from e

def strict_equal(left,right):
    """Python bool/float equality must not admit forged exact integer fields."""
    if type(left) is not type(right): return False
    if type(left) is dict: return set(left)==set(right) and all(strict_equal(left[k],right[k]) for k in left)
    if type(left) is list: return len(left)==len(right) and all(strict_equal(a,b) for a,b in zip(left,right))
    return left==right

def open_input(path):
    p=Path(path)
    check(p.is_absolute() and str(p)==os.path.normpath(str(p)),'Noncanonical absolute input')
    current=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in p.parts[1:-1]:
            nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=current)
            os.close(current); current=nxt
        fd=os.open(p.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=current)
        try: check(stat.S_ISREG(os.fstat(fd).st_mode),'Nonregular input')
        except BaseException: os.close(fd); raise
        return fd
    finally: os.close(current)

def file_state(fd):
    s=os.fstat(fd)
    return (s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def sum_fd(fd,maximum):
    state=file_state(fd); check(0 < state[3] <= maximum,'Input size bound')
    h=hashlib.sha256(); n=0
    while n<state[3]:
        b=os.pread(fd,min(1024**2,state[3]-n),n); check(b,'Truncated input'); h.update(b); n+=len(b)
    check(file_state(fd)==state and not os.pread(fd,1,n),'Input changed')
    return {'sha256':h.hexdigest(),'size':n}

def read_authenticated(path,expected,maximum):
    fields(expected,{'sha256','size'})
    check(type(expected['size']) is int and expected['size']>0 and type(expected['sha256']) is str and
          re.fullmatch('[0-9a-f]{64}',expected['sha256']),'Malformed reference')
    fd=open_input(path)
    try:
        check(sum_fd(fd,maximum)==expected,'Evidence digest mismatch')
        data=os.pread(fd,expected['size']+1,0)
        check(len(data)==expected['size'] and hashlib.sha256(data).hexdigest()==expected['sha256'],'Evidence snapshot changed')
        return data
    finally: os.close(fd)

def independently_select(pair_path,pair_sha):
    check(type(pair_sha) is str and re.fullmatch('[0-9a-f]{64}',pair_sha),'Malformed pair SHA')
    fd=open_input(pair_path)
    try:
        pair_ref=sum_fd(fd,LIMITS['json_bytes']); check(pair_ref['sha256']==pair_sha,'Unauthenticated pair')
        pair_raw=os.pread(fd,pair_ref['size']+1,0)
        check(len(pair_raw)==pair_ref['size'] and hashlib.sha256(pair_raw).hexdigest()==pair_sha,'Changed pair snapshot')
    finally: os.close(fd)
    pair=parse_json(pair_raw); fields(pair,PAIR_FIELDS)
    check(type(pair['schema']) is int and pair['schema']==1 and pair['kind']=='wonad-grapheneos-incremental-pair'
          and pair['target']=='frankel','Wrong pair schema')
    values={}; root=Path(pair_path).parent.parent
    for label in ('predecessor','successor'):
        e=pair[label]; fields(e,END_FIELDS)
        number=e['number']; check(type(number) is str and re.fullmatch('[0-9]{10}',number),'Bad build number')
        relative=number+'/release-frankel-'+number+'/release-receipt.json'
        fields(e['receipt'],{'path','sha256','size'}); check(e['receipt']['path']==relative,'Wrong endpoint origin')
        full_ref={k:e['receipt'][k] for k in ('sha256','size')}
        raw=read_authenticated(root/relative,full_ref,LIMITS['json_bytes']); full=parse_json(raw); fields(full,FULL_FIELDS)
        check(type(full['schema']) is int and full['schema']==4 and full['kind']=='wonad-grapheneos-release'
              and strict_equal(full['target'],DEVICE),'Wrong full receipt schema/target')
        fields(full['build'],{'number','post_build','timestamp','datetime_utc'})
        check(full['build']['number']==number and type(full['build']['timestamp']) is int and
              full['build']['timestamp']>0 and type(full['build']['post_build']) is str and full['build']['post_build'],'Bad build fields')
        combined={'number':number,'receipt':e['receipt']}
        for key in END_FIELDS-{'number','receipt'}: combined[key]=full[key]
        check(strict_equal(combined,e),'Endpoint JSON cross-binding mismatch')
        check(type(full['apk_signer_sha256']) is str and re.fullmatch('[0-9a-f]{64}',full['apk_signer_sha256']) and
              type(full['updater_stage']) is dict and type(full['updater_stage'].get('update_url')) is str and
              full['updater_stage']['update_url'],'Missing receipted lineage')
        for key in ('source','grapheneos_lock','wonad_stage','phase1_provenance'):
            check(type(full[key]) is dict and full[key],'Empty receipted identity')
        check(type(full['artifacts']) is dict and full['artifacts'].get('signed_target_files')=='frankel-target_files.zip'
              and type(full['files']) is dict,'Wrong artifact selector')
        archive_ref=full['files'].get('frankel-target_files.zip'); fields(archive_ref,{'sha256','size'})
        check(type(archive_ref['size']) is int and archive_ref['size']>0 and type(archive_ref['sha256']) is str and
              re.fullmatch('[0-9a-f]{64}',archive_ref['sha256']),'Invalid archive reference')
        values[label]={'endpoint':e,'full_ref':full_ref,'full_raw':raw,'archive_ref':archive_ref,
                       'archive_path':root/relative.rsplit('/',1)[0]/'frankel-target_files.zip'}
    a,b=values['predecessor']['endpoint'],values['successor']['endpoint']
    check(int(b['number'])>int(a['number']) and b['build']['timestamp']>a['build']['timestamp'],'Nonmonotonic pair')
    check(a['apk_signer_sha256']==b['apk_signer_sha256'] and
          a['updater_stage']['update_url']==b['updater_stage']['update_url'],'Changed receipted lineage')
    p=Path(pair_path)
    check(p.parent.name==b['number'] and root.name=='releases' and
          p.name==f"frankel-incremental-{a['number']}-{b['number']}-receipt.json",'Noncanonical pair layout')
    return pair_raw,pair_ref,values

def at(fd,where,length):
    check(where>=0 and length>=0,'Invalid ZIP range')
    b=os.pread(fd,length,where); check(len(b)==length,'Truncated ZIP record'); return b

def unzip64(extra,values):
    blocks={}; cursor=0
    while cursor<len(extra):
        check(cursor+4<=len(extra),'Broken extra TLV'); tag,n=struct.unpack_from('<HH',extra,cursor); cursor+=4
        check(cursor+n<=len(extra) and tag not in blocks,'Duplicate/broken extra TLV')
        blocks[tag]=extra[cursor:cursor+n]; cursor+=n
    z=blocks.get(1,b''); cursor=0; expanded=[]
    for v,marker,width in values:
        if v==marker:
            check(cursor+width<=len(z),'Needed ZIP64 extra missing'); v=int.from_bytes(z[cursor:cursor+width],'little'); cursor+=width
        expanded.append(v)
    check(1 not in blocks or cursor==len(z),'Unexpected Zip64 fields')
    return expanded

def scan_directory(fd,limits):
    n=os.fstat(fd).st_size; check(22<=n<=limits['archive_bytes'],'ZIP byte ceiling')
    start=max(0,n-65557); tail=at(fd,start,n-start); found=[]
    for i in range(len(tail)-21):
        if tail[i:i+4]==b'PK\x05\x06':
            data=struct.unpack_from('<4s4H2IH',tail,i)
            if i+22+data[7]==len(tail): found.append((start+i,data))
    check(len(found)==1,'Nonterminal/ambiguous EOCD'); end,data=found[0]
    check(data[1]==data[2]==0 and data[3]==data[4],'Split ZIP unsupported')
    count,size,offset=data[4:7]; stop=end
    locator=end>=20 and at(fd,end-20,4)==b'PK\x06\x07'
    is64=locator or count==65535 or size==0xffffffff or offset==0xffffffff
    if is64:
        check(locator,'Missing ZIP64 locator'); loc=struct.unpack('<4sIQI',at(fd,end-20,20))
        check(loc[1]==0 and loc[3]==1,'Split ZIP64'); wide=struct.unpack('<4sQ2H2I4Q',at(fd,loc[2],56))
        check(wide[0]==b'PK\x06\x06' and 44<=wide[1]<=1024**2 and loc[2]+12+wide[1]==end-20 and
              wide[4]==wide[5]==0 and wide[6]==wide[7],'Malformed ZIP64 end')
        check(all(s==m or s==v for s,v,m in ((count,wide[7],65535),(size,wide[8],0xffffffff),(offset,wide[9],0xffffffff))),
              'Conflicting wide end values')
        count,size,offset=wide[7:10]; stop=loc[2]
    check(1<=count<=limits['entries'] and 46<=size<=limits['central_bytes'] and
          0<=offset<stop and offset+size==stop,'Central directory admission bound')
    parsed=[]; pos=offset
    while pos<stop:
        check(len(parsed)<count and len(parsed)<limits['entries'],'Unadvertised central entry')
        h=struct.unpack('<4s6H3I5H2I',at(fd,pos,46)); check(h[0]==b'PK\x01\x02','Wrong central signature')
        lengths=h[10]+h[11]+h[12]
        check(0<h[10]<=limits['name_bytes'] and pos+46+lengths<=stop,'Central entry length bound')
        value=at(fd,pos+46,lengths); name=value[:h[10]]; extra=value[h[10]:h[10]+h[11]]
        usize,csize,local,disk=unzip64(extra,[(h[9],0xffffffff,8),(h[8],0xffffffff,8),(h[16],0xffffffff,8),(h[13],65535,4)])
        check(disk==0,'Split member')
        parsed.append((name,extra,h[3],h[4],h[7],usize,csize,local,h[1]>>8,h[15])); pos+=46+lengths
    check(pos==stop and len(parsed)==count,'Central exact count mismatch')
    summary=dict(zip64=is64,entry_count=count,central_directory_offset=offset,central_directory_bytes=size,
                 central_directory_sha256=hashlib.sha256(at(fd,offset,size)).hexdigest(),eocd_offset=end,comment_bytes=data[7])
    return parsed,summary

def local_extent(fd,entry,cd_start):
    name,extra,flags,method,crc,usize,csize,local,creator,ext=entry
    check(0<=local<cd_start,'Bad physical local offset'); h=struct.unpack('<4s5H3I2H',at(fd,local,30))
    check(h[0]==b'PK\x03\x04' and h[2]==flags and h[3]==method,'Local flags/method mismatch')
    value=at(fd,local+30,h[9]+h[10]); check(value[:h[9]]==name,'Local name mismatch')
    actual_u,actual_c=unzip64(value[h[9]:],[(h[8],0xffffffff,8),(h[7],0xffffffff,8)])
    data_start=local+30+len(value); finish=data_start+csize
    check(finish<=cd_start,'Physical member outside data section')
    if flags&8:
        check(h[6] in (0,crc) and actual_u in (0,usize) and actual_c in (0,csize),'Local streaming values conflict')
        w=8 if h[7]==0xffffffff or h[8]==0xffffffff or usize>0xffffffff or csize>0xffffffff else 4
        base=finish+4 if at(fd,finish,4)==b'PK\x07\x08' else finish
        d=at(fd,base,4+2*w)
        check(int.from_bytes(d[:4],'little')==crc and int.from_bytes(d[4:4+w],'little')==csize and
              int.from_bytes(d[4+w:],'little')==usize,'Bad streaming data descriptor')
        finish=base+len(d); check(finish<=cd_start,'Descriptor outside data section')
    else: check((h[6],actual_u,actual_c)==(crc,usize,csize),'Local nonstreamed values conflict')
    return data_start,finish

def independently_decompress(fd,start,compressed,method,expanded,chunk):
    if method==0:
        check(compressed==expanded,'Stored declared lengths differ')
        for relative in range(0,compressed,chunk):
            yield at(fd,start+relative,min(chunk,compressed-relative))
    else:
        inflate=zlib.decompressobj(wbits=-15); read=0; residue=b''
        while not inflate.eof:
            if not residue and read<compressed:
                residue=at(fd,start+read,min(chunk,compressed-read)); read+=len(residue)
            input_present=bool(residue)
            output=inflate.decompress(residue,max_length=chunk)
            residue=inflate.unconsumed_tail
            if output: yield output
            check(not inflate.unused_data,'Unconsumed trailing compressed bytes')
            if inflate.eof:
                check(read==compressed and not residue,'Extra bytes after deflate stream'); break
            check(input_present or output,'Deflate stream ended prematurely')
        check(inflate.eof and not residue and not inflate.unused_data,'Deflate stream not complete')

def rederive_archive(path,expected,label,limits=LIMITS):
    fd=open_input(path)
    try:
        start_state=file_state(fd); check(sum_fd(fd,limits['archive_bytes'])==expected,'Archive identity mismatch')
        directory,summary=scan_directory(fd,limits); members=[]; listing=[]; ranges=[]; paths={}; total=0
        with os.fdopen(os.dup(fd),'rb') as f,zipfile.ZipFile(f,allowZip64=True) as z:
            infos=z.infolist(); check(len(infos)==len(directory),'ZIP parser count disagreement')
            for i,(e,info) in enumerate(zip(directory,infos)):
                name_raw,extra,flags,method,crc,usize,csize,local,creator,ext=e
                check(method in (0,8) and not flags&~(8|2048|2|4) and (method==8 or not flags&6),'ZIP features unsupported')
                directory_name=name_raw.endswith(b'/'); type_bits=(ext>>16)&0o170000 if creator==3 else 0
                check(not ext&16 or directory_name,'DOS directory flag conflict')
                check(type_bits in (0,stat.S_IFREG,stat.S_IFDIR,stat.S_IFLNK) and
                      (type_bits==0 or (type_bits==stat.S_IFDIR)==directory_name),'ZIP type conflict')
                kind='directory' if directory_name else 'symlink' if type_bits==stat.S_IFLNK else 'regular'
                try: name=name_raw.decode('utf-8' if flags&2048 else 'cp437')
                except UnicodeError as e: raise AuditError('Bad ZIP name encoding') from e
                path_name=name[:-1] if directory_name else name
                check(name and '\\' not in name and not any(ord(c)<32 or 127<=ord(c)<=159 for c in name) and path_name and
                      not path_name.startswith('/') and all(p not in ('','.','..') for p in path_name.split('/')),'Unsafe ZIP name')
                check(path_name not in paths,'Physical namespace alias'); paths[path_name]=kind
                check(info.orig_filename==info.filename==name and info.file_size==usize and info.compress_size==csize and
                      info.CRC==crc and info.header_offset==local and info.compress_type==method and info.flag_bits==flags,'ZIP parser entry disagreement')
                check(usize<=limits['member_bytes'] and csize<=limits['archive_bytes'] and
                      (kind!='symlink' or usize<=limits['symlink_bytes']) and (kind!='directory' or usize==0),'Expanded bounds')
                total+=usize; check(total<=limits['total_bytes'],'Total expansion bound')
                data_start,finish=local_extent(fd,e,summary['central_directory_offset']); ranges.append((local,finish))
                h=hashlib.sha256(); running_crc=0; length=0
                for block in independently_decompress(fd,data_start,csize,method,usize,limits['chunk_bytes']):
                    length+=len(block); check(length<=usize and length<=limits['member_bytes'],'Stream expansion bound')
                    h.update(block); running_crc=zlib.crc32(block,running_crc)
                check(length==usize and running_crc==crc,'Observed size/CRC disagreement')
                row={'endpoint':label,'namespace':'target-files','member':path_name,'zip_name':name,'central_index':i,
                     'type':kind,'creator_system':creator,'unix_mode':ext>>16,'external_attr':ext,'flags':flags,
                     'compression_method':method,'compressed_size':csize,'expanded_size':length,'crc32':f'{running_crc:08x}',
                     'sha256':h.hexdigest(),'local_header_offset':local,'compressed_data_offset':data_start,'raw_listing_index':i}
                members.append(row); listing.append(dict(row,name_bytes_hex=name_raw.hex(),extra_sha256=hashlib.sha256(extra).hexdigest()))
        previous=0
        for lo,hi in sorted(ranges): check(lo>=previous,'Overlapping member extents'); previous=hi
        for p in paths:
            pieces=p.split('/')
            check(all(paths.get('/'.join(pieces[:n]),'directory')=='directory' for n in range(1,len(pieces))),'Nondirectory prefix')
        check(sum_fd(fd,limits['archive_bytes'])==expected and file_state(fd)==start_state,'Archive drifted')
        current=os.stat(path,follow_symlinks=False)
        check((current.st_dev,current.st_ino)==start_state[:2],'Archive path exchanged')
        summary.update(expanded_total=total,regular_count=sum(r['type']=='regular' for r in members),
                       directory_count=sum(r['type']=='directory' for r in members),symlink_count=sum(r['type']=='symlink' for r in members))
        return sorted(members,key=lambda r:r['member']),listing,summary
    except (zipfile.BadZipFile,RuntimeError,NotImplementedError,EOFError,struct.error,UnicodeError,zlib.error) as e:
        raise AuditError('ZIP rederivation failed: '+str(e)) from e
    finally: os.close(fd)

def evidence_bytes(directory,row,name,maximum):
    fields(row,{'path','sha256','size'}); check(row['path']==name,'Evidence path relabelled')
    return read_authenticated(directory/name,{k:row[k] for k in ('sha256','size')},maximum)

def rows_from_jsonl(data):
    check(data.endswith(b'\n'),'Noncanonical JSONL ending')
    rows=[]
    for line in data.splitlines(keepends=True):
        row=parse_json(line)
        canonical=(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
        check(line==canonical,'Noncanonical ledger JSON'); rows.append(row)
    return rows

def audit(receipt_path,receipt_sha,pair_path,pair_sha,implementation):
    receipt_path=Path(receipt_path); fd=open_input(receipt_path)
    try:
        receipt_ref=sum_fd(fd,LIMITS['json_bytes']); check(receipt_ref['sha256']==receipt_sha,'Inventory receipt not authenticated')
        raw=os.pread(fd,receipt_ref['size']+1,0); check(hashlib.sha256(raw).hexdigest()==receipt_sha,'Receipt snapshot changed')
    finally: os.close(fd)
    receipt=parse_json(raw)
    fields(receipt,{'schema','kind','status','scope','pair','implementation','endpoints'}|FALSE_CLAIMS)
    check(type(receipt['schema']) is int and receipt['schema']==1 and receipt['kind']=='phase1_authenticated_target_files_archive_inventory'
          and receipt['status']=='observed' and receipt['scope']=='authenticated_pair_selected_target_files_archive_observations','Wrong observation scope')
    check(all(receipt[k] is False for k in FALSE_CLAIMS),'Unsupported qualification claim')
    check(strict_equal(receipt['implementation'],dict(implementation,structural_policy=LIMITS)),'Active implementation identity changed')
    pair_raw,pair_ref,selection=independently_select(pair_path,pair_sha)
    fields(receipt['pair'],{'origin','sha256','size','snapshot'})
    check(receipt['pair']['origin']==str(pair_path) and strict_equal({k:receipt['pair'][k] for k in ('sha256','size')},pair_ref),'Pair record mismatch')
    directory=receipt_path.parent
    check(evidence_bytes(directory,receipt['pair']['snapshot'],'pair.json',LIMITS['json_bytes'])==pair_raw,'Pair snapshot mismatch')
    fields(receipt['endpoints'],{'predecessor','successor'})
    for label in ('predecessor','successor'):
        entry=selection[label]; observed=receipt['endpoints'][label]
        fields(observed,{'build','release_receipt','receipted_endpoint_identity','archive','fd_observation','zip_structure'})
        check(strict_equal(observed['receipted_endpoint_identity'],entry['endpoint']) and
              strict_equal(observed['build'],{k:entry['endpoint']['build'][k] for k in ('number','timestamp','post_build')}),'Endpoint record mismatch')
        f=observed['release_receipt']; fields(f,{'origin','sha256','size','snapshot'})
        check(f['origin']==entry['endpoint']['receipt']['path'] and
              strict_equal({k:f[k] for k in ('sha256','size')},entry['full_ref']),'Full receipt origin/hash mismatch')
        check(evidence_bytes(directory,f['snapshot'],label+'-release.json',LIMITS['json_bytes'])==entry['full_raw'],'Full snapshot mismatch')
        expected_archive=dict(role='signed_target_files',origin=f['origin'].rsplit('/',1)[0]+'/frankel-target_files.zip',**entry['archive_ref'])
        check(strict_equal(observed['archive'],expected_archive),'Archive record mismatch')
        state=observed['fd_observation']
        fields(state,{'device','inode','mode','size','mtime_ns','ctime_ns','before_hash','after_hash','path_still_names_fd'})
        check(all(type(state[k]) is int and state[k]>=0 for k in ('device','inode','mode','size','mtime_ns','ctime_ns')) and
              stat.S_ISREG(state['mode']) and state['size']==entry['archive_ref']['size'] and state['path_still_names_fd'] is True and
              strict_equal(state['before_hash'],entry['archive_ref']) and strict_equal(state['after_hash'],entry['archive_ref']),'Invalid FD observation')
        members,listing,summary=rederive_archive(entry['archive_path'],entry['archive_ref'],label)
        structure=observed['zip_structure']; fields(structure,set(summary)|{'member_inventory','raw_listing'})
        check(strict_equal({k:structure[k] for k in summary},summary),'Archive structural observation mismatch')
        actual_members=rows_from_jsonl(evidence_bytes(directory,structure['member_inventory'],label+'-members.jsonl',LIMITS['ledger_bytes']))
        actual_listing=rows_from_jsonl(evidence_bytes(directory,structure['raw_listing'],label+'-raw.jsonl',LIMITS['ledger_bytes']))
        check(strict_equal(actual_members,members) and strict_equal(actual_listing,listing),'Independent member/listing mismatch')
    # Original receipts must still resolve to exactly the authenticated snapshots.
    end_pair,end_ref,end_selection=independently_select(pair_path,pair_sha)
    check(end_pair==pair_raw and end_ref==pair_ref and all(end_selection[r]['full_raw']==selection[r]['full_raw'] for r in selection),'Receipt drift at audit end')
    for entry in selection.values():
        fd=open_input(entry['archive_path'])
        try: check(sum_fd(fd,LIMITS['archive_bytes'])==entry['archive_ref'],'Archive drift at audit end')
        finally: os.close(fd)
    return dict(schema=1,kind='phase1_independently_audited_archive_observations',status='observed',
                inventory_receipt=receipt_ref,pair_receipt=pair_ref,release_gate_closed=False,
                cryptography_performed=False,package_identity_derived=False,extraction_performed=False,runtime_qualified=False)

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inventory-receipt',required=True,type=Path)
    p.add_argument('--expected-inventory-receipt-sha256',required=True)
    p.add_argument('--pair-receipt',required=True,type=Path)
    p.add_argument('--expected-pair-receipt-sha256',required=True)
    a=p.parse_args(argv)
    try:
        check('__authenticated_implementation__' in globals(),'Use the authenticated run_snapshot.py launcher')
        print(json.dumps(audit(a.inventory_receipt,a.expected_inventory_receipt_sha256,a.pair_receipt,
                              a.expected_pair_receipt_sha256,globals()['__authenticated_implementation__']),sort_keys=True))
        return 0
    except (AuditError,OSError) as e:
        print('FAIL: '+str(e),file=sys.stderr); return 1

if __name__=='__main__': sys.exit(main())
