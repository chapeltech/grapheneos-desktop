#!/usr/bin/env python3
"""Reviewed bootstrap: authenticate/compile the same two captured source bytes.

Caller separately authenticates this literal bootstrap's published source hash.
It selects no arbitrary Python file and never consults import/bytecode caches
for producer/auditor. Invoke with source pins and '--' before component args.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from types import ModuleType
import zipfile
import zlib

def capture(path,limit):
    path=Path(path)
    if not path.is_absolute() or path.resolve(strict=True)!=path:
        raise ValueError('Missing/aliased bootstrap dependency')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=limit:
            raise ValueError('Nonordinary/bounded bootstrap dependency')
        parts=[]; n=0
        while n<before.st_size:
            block=os.read(fd,min(1024**2,before.st_size-n))
            if not block: raise ValueError('Truncated bootstrap dependency')
            parts.append(block); n+=len(block)
        after=os.fstat(fd)
        key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if key(before)!=key(after) or os.read(fd,1): raise ValueError('Bootstrap dependency drift')
        data=b''.join(parts)
        return data,{'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}
    finally: os.close(fd)

def authenticated_sources(directory,producer_sha,auditor_sha):
    snapshots={}; refs={}
    for label,expected,name in (('producer',producer_sha,'produce_archive_inventory.py'),
                                ('auditor',auditor_sha,'audit_archive_inventory.py')):
        if type(expected) is not str or re.fullmatch('[0-9a-f]{64}',expected) is None:
            raise ValueError('Expected source SHA required')
        raw,ref=capture(directory/name,2*1024**2)
        if ref['sha256']!=expected: raise ValueError('Authenticated source mismatch: '+label)
        snapshots[label]=raw; refs[label]={'name':name,'sha256':ref['sha256'],'size':ref['size']}
    return snapshots,refs

def execute_snapshot(raw,path,implementation,args):
    module=ModuleType('_wonad_archive_snapshot')
    module.__file__=str(path); module.__package__=''; module.__loader__=None; module.__spec__=None
    module.__dict__['__authenticated_implementation__']=implementation
    exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
    return module.main(args)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('produce','audit'))
    parser.add_argument('--expected-producer-sha256',required=True)
    parser.add_argument('--expected-auditor-sha256',required=True)
    values=list(sys.argv[1:] if argv is None else argv)
    boundary=values.index('--') if '--' in values else len(values)
    args=parser.parse_args(values[:boundary])
    try:
        directory=Path(__file__).resolve().parent
        snapshots,implementation=authenticated_sources(directory,args.expected_producer_sha256,args.expected_auditor_sha256)
        _,python_ref=capture(Path(sys.executable).resolve(strict=True),64*1024**2)
        implementation['interpreter']=dict(python_ref,version=sys.version)
        _,implementation['stdlib_zipfile']=capture(Path(zipfile.__file__).resolve(strict=True),2*1024**2)
        _,zref=capture(Path(zlib.__file__).resolve(strict=True),16*1024**2)
        implementation['zlib_runtime_identity']=dict(zref,compiled_version=zlib.ZLIB_VERSION,runtime_version=zlib.ZLIB_RUNTIME_VERSION)
        _,implementation['bootstrap']=capture(Path(__file__).resolve(strict=True),2*1024**2)
        component='producer' if args.mode=='produce' else 'auditor'
        forwarded=values[boundary+1:]
        path=directory/('produce_archive_inventory.py' if component=='producer' else 'audit_archive_inventory.py')
        return execute_snapshot(snapshots[component],path,implementation,forwarded)
    except (ValueError,OSError) as e:
        print('FAIL: '+str(e),file=sys.stderr); return 1

if __name__=='__main__': sys.exit(main())
