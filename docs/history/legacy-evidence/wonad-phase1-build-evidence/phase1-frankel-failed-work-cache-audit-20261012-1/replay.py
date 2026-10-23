#!/usr/bin/python3
"""Read-only rejoin the retained observations; independent epochs remain distinct."""
import hashlib
import json
import os
from pathlib import Path
import stat

B = Path(__file__).resolve().parent
s = json.loads((B/'summary-observation.json').read_bytes())
verified = []
for a in s['attempts']:
    g = a['generation']
    p = json.loads(Path(a['references']['preflight']['path']).read_bytes())
    r = json.loads(Path(a['references']['result']['path']).read_bytes())
    l = json.loads(Path(a['references']['lock']['path']).read_bytes())
    o = json.loads((B/f'g{g}-observation.json').read_bytes())['attempt']
    assert p['nonce'] == r['container']['nonce']
    v = p['create_argv']
    assert v[v.index('--name')+1] == r['container']['name']
    assert l['source'] == r['source'] and l['container'] == r['container']['name']
    assert f"org.wonad.phase1.vendor-attempt={p['nonce']}" in v
    for row in list(r['inputs']['source_directory_identities'].values()) + [
            r['inputs']['cache']['directory'], r['inputs']['cache']['archive']]:
        m = os.lstat(row['path'])
        assert (m.st_dev,m.st_ino,m.st_uid,m.st_gid,stat.S_IMODE(m.st_mode)) == (
            row['device'],row['inode'],row['uid'],row['gid'],row['mode'])
    assert o['references'] == a['references']
    for name, ref in o['references'].items():
        raw = Path(ref['path']).read_bytes()
        assert len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256']
    assert o['cache_census']['root'] == a['cache_census']['root']
    assert o['archive_preserved'] == a['archive_preserved']
    assert o['container']['state'] == a['container']['state']
    assert o['container']['profile'] == a['container']['profile']
    # Docker Mounts array ordering can change between inspections. Each raw
    # transcript remains individually hashed; audit.py validates its exact set.
    raw = o['container']['stdout'].encode()
    assert hashlib.sha256(raw).hexdigest() == o['container']['stdout_sha256']
    parsed = json.loads(raw)[0]
    assert parsed['Id'] == r['container']['id'] and parsed['State'] == o['container']['state']
    assert o['cache_census']['entry_count'] == len(o['cache_census']['entries'])
    assert all(x['uid'] == x['gid'] == 1000 for x in o['cache_census']['entries'])
    assert o['cache_census']['observed_unshared_extent_bytes'] == sum(
        x.get('fiemap',{}).get('observed_unshared_extent_bytes',0) for x in o['cache_census']['entries'])
    verified.append({'generation':g,'source_directory_and_factory_metadata_match':True,
                     'original_nonce_name_lock_joins_match':True,
                     'separate_observation_reference_and_scalar_profile_join':True,
                     'cache_uid_gid_1000':True,
                     'container_inspect_sha256':o['container']['stdout_sha256']})
refs = {p.name:{'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
        for p in sorted(B.iterdir()) if p.is_file() and p.name not in ('replay-output.json','owner-record.json')}
print(json.dumps({'schema':1,'kind':'phase1_failed_vendor_work_readonly_observation_replay_v1',
                  'verified':verified,'refs':refs,'result':'PASS','deleted':False},sort_keys=True))
