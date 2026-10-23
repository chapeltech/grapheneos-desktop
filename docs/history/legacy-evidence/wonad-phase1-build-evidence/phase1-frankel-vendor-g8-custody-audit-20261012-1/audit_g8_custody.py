#!/usr/bin/env python3
"""Observe exact historical custody; stdout only, no cleanup/producer execution."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time
import types

EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
REPO = Path('/u/elric/tree/wonad')
CANDIDATE = EVIDENCE/'phase1-frankel-vendor-terminal-outcome-candidate-20261012-1/candidate/run_frankel_vendor.py'
CANDIDATE_SHA = '3c26be80b3f5bb0bbc747811e9d4f40780800897211ad559632193e96bbb5d05'
CID = '79dbd12fcdd9371bb1616bbc1d87c07d788eddf11f8a6e56a3d613ab8d30260b'
NAME = 'wonad-phase1-frankel-vendor-2026100600-008'
NONCE = 'e1569c2277e85705b31b81829a71c89cc24a8e57b46028a72693cd0a6e193c06'
INPUTS = {
 'bridge': (EVIDENCE/'prepare-phase1-frankel-vendor-cache-20261012-8.sh','9e2c4fac586f4abe76946d90e7b348bb0c6f7ec2f11c61c983a2607890aafe2a'),
 'result': (EVIDENCE/'phase1-frankel-baseline-vendor-cache-20261012-8.result.json','9a63f73c24ad71c4fb6f72fcbe894d38acebcdf6f838fc9ca849d5a12d84806f'),
 'preflight': (EVIDENCE/'phase1-frankel-baseline-vendor-cache-20261012-8.preflight.json','5448176b9b7f81babfb6bdd8bc1b8b556ac6b13c6ec30e86741c9f9e4d6d13c5'),
 'attempt_lock': (EVIDENCE/'phase1-frankel-baseline-vendor-cache-20261012-8.lock.json','f685ec59f97e024423bd18820ccca12fcdd920c4de5999af9fcd75b1d6f6cf5c'),
 'root_oom_observation': (EVIDENCE/'phase1-frankel-vendor-g8-actual-oom-root-observation-20261012-1.json','c602d17bcd37ff22db022c08e7428d9151f45bcb69778e8c077d9b23f965b164'),
 'candidate_freeze': (EVIDENCE/'phase1-frankel-vendor-terminal-outcome-candidate-20261012-1/freeze-review.json','32797c8e7b4170ec4932f1cb58b0f7b3114e941825c6771389169047af750524'),
 'provenance': (REPO/'android/tools/phase1_provenance.py','33ffa48ccf4a89709e8b3bbf0770245bd9039d164c8a02755f74f2aaec0a8887'),
}
TARGETS = ('vendor/adevtool/node_modules','vendor/adevtool/.cache',
           'vendor/adevtool/cache','vendor/adevtool/.yarn','vendor/adevtool/lib',
           'vendor/adevtool/dist','out_adevtool_deps','vendor/adevtool/dl')

def metadata(path):
    value=path.lstat()
    return {'path':str(path),'device':value.st_dev,'inode':value.st_ino,
            'uid':value.st_uid,'gid':value.st_gid,'mode':stat.S_IMODE(value.st_mode),
            'bytes':value.st_size,'nlink':value.st_nlink,'is_symlink':stat.S_ISLNK(value.st_mode),
            'is_directory':stat.S_ISDIR(value.st_mode),'is_regular':stat.S_ISREG(value.st_mode)}

def main():
    record={'schema':1,'status':'incomplete_read_only_custody_observation',
            'scope':'actual exact-owned historical40GiB stopped-state/source custody snapshot; NOT cleanup authorization/vendor success/G9 admission',
            'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'started_monotonic_ns':time.monotonic_ns(),
            'actions':{'docker_read_only_inspect_only':True,'docker_called':False,'cache_deleted':False,
                       'container_restarted_or_removed':False,'initial_inputs_called':False,
                       'producer_execute_or_resources_called':False,'g9_admission_or_run':False}}
    source_fd=None
    try:
        payload=CANDIDATE.read_bytes()
        if hashlib.sha256(payload).hexdigest()!=CANDIDATE_SHA:
            raise ValueError('Frozen terminal-only40 candidate identity differs')
        vendor=types.ModuleType('historical_g8_terminal_validator')
        vendor.__file__=str(REPO/'android/tools/run_frankel_vendor.py')
        sys.modules[vendor.__name__]=vendor
        exec(compile(payload,vendor.__file__,'exec'),vendor.__dict__)
        if vendor.MEMORY!=40*1024**3:
            raise ValueError('Historical validator is not exact40GiB')
        refs,values={},{}
        for name,(path,digest) in INPUTS.items():
            raw,ref=vendor.capture_regular(path,8*1024**2)
            vendor.require(ref['sha256']==digest,'Historical input identity differs: '+name)
            refs[name]=ref
            values[name]=raw.decode('utf-8') if name in ('bridge','provenance') else vendor.unique_json(raw,name)
        record['authenticated_inputs']=refs
        before=values['preflight']; result=values['result']; lock=values['attempt_lock']
        vendor.require(before.get('schema')==1 and before.get('kind')=='phase1_frankel_vendor_host_builder_preflight_v1' and
                       result.get('schema')==1 and result.get('kind')=='phase1_frankel_vendor_host_builder_result_v1' and
                       result.get('runtime_qualified') is False and result.get('generated_vendor') is None,
                       'Historical receipt role/schema differs')
        invocation=shlex.split(values['bridge'].split('\nexec ',1)[1].replace('\\\n',''))
        vendor.require(invocation[:4]==['/usr/bin/python3.14','-B',vendor.__file__,'$1'],
                       'Historical literal interpreter/helper/action differs')
        config=vendor.config_from_args(vendor.build_parser().parse_args(['--check-only',*invocation[4:]]))
        vendor.require(config.container==NAME and result['container']['id']==CID and
                       result['container']['name']==NAME and result['container']['nonce']==NONCE and before['nonce']==NONCE and
                       result['source']==before['source']==str(config.source),
                       'Historical source/container/nonce joins differ')
        vendor.require(result['inputs']['preflight']==refs['preflight'] and
                       before['repository_inputs']==result['inputs']['repository'] and
                       before['reflink_workspace']==result['work'] and
                       before['factory_cache']==result['inputs']['cache'],
                       'Historical preflight/result input/work/cache binding differs')
        vendor.require(vendor.create_command(config,NONCE)==before['create_argv'],
                       'Historical full create-argv does not match exact40GiB reconstructed config')
        for name,rows in (('repository',config.repo_inputs),('source',config.source_inputs)):
            historical=(before['repository_inputs'] if name=='repository' else before['second_source']['source_inputs'])
            vendor.require(set(historical)==set(rows),'Historical named input set differs: '+name)
            for relative,digest in rows.items():
                vendor.require(historical[relative]['sha256']==digest,
                               'Historical literal pin differs: '+relative)
        vendor.require(set(lock)=={'schema','kind','pid','source','container','created_unix'} and
                       lock['schema']==1 and lock['kind']=='phase1_frankel_vendor_attempt_lock_v1' and
                       lock['source']==str(config.source) and lock['container']==NAME and
                       type(lock['pid']) is int and lock['pid']>0 and
                       type(lock['created_unix']) is int and lock['created_unix']>0,
                       'Historical attempt-lock role/owner fields differ')
        original_ids=result['inputs']['source_directory_identities']
        vendor.require(before['first_source']['topology']['directory_identities']==original_ids and
                       before['second_source']['topology']['directory_identities']==original_ids,
                       'Historical source-directory generations disagree')
        record['reconstructed_old_config']={'container':config.container,'source':str(config.source),
            'repo':str(config.repo),'work':str(config.work),'builder':config.builder_image,
            'memory_bytes':vendor.MEMORY,'memory_swap_bytes':vendor.MEMORY,'nonce':NONCE,
            'old_helper_sha256':config.repo_inputs['android/tools/run_frankel_vendor.py'],
            'full_create_argv_matches_authenticated_preflight':True,
            'current_helper_not_used_as_old_historical_authority':True}
        source_fd=os.open(config.source,os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW)
        fcntl.flock(source_fd,fcntl.LOCK_SH|fcntl.LOCK_NB)
        record['source_lock']={'kind':'shared_NONBLOCK_directory_flock_readonly_fd',
                               'acquired':True,'released_before_publication':False,
                               'not_future_exclusive_cleanup_lock_or_reservation':True}
        current_ids=vendor.require_source_directory_identities(config,original_ids,source_fd)
        work=vendor.directory(config.work,uid=os.getuid(),gid=os.getgid())
        vendor.require(work==result['work']['directory'],'Historical workspace directory identity changed')
        current_lock_raw,current_lock_ref=vendor.capture_regular(config.attempt_lock,64*1024)
        lock_meta=metadata(config.attempt_lock)
        current_lock_join={**current_lock_ref,**{k:lock_meta[k] for k in ('device','inode','uid','gid','mode')}}
        vendor.require(current_lock_join==result['inputs']['attempt_lock']['initial']==result['inputs']['attempt_lock']['final'],
                       'Historical attempt-lock current inode/content/owner binding changed')
        vendor.require(current_lock_raw==vendor.canonical(lock),'Historical lock no longer canonical exactbytes')
        record['source_directory_identities']=current_ids
        record['source_directories_match_original_preflight_and_result']=True
        record['work_directory_identity']=work
        record['work_directory_matches_original']=True
        record['attempt_lock_identity']=current_lock_join
        record['attempt_lock_matches_original_initial_and_final']=True
        record['attempt_lock_creator']=lock
        # Authentication uses the original old Docker endpoint/custody, not a selected remote context.
        cli=Path('/usr/bin/docker'); oldcli=before['docker_authority']['cli']
        cli_meta=metadata(cli)
        vendor.require(str(cli.resolve(strict=True))==oldcli['realpath'] and
                       cli_meta['is_regular'] and not cli_meta['is_symlink'] and
                       all(cli_meta[k]==oldcli[k] for k in ('device','inode','uid','gid')) and
                       cli.stat().st_mode==oldcli['mode'] and cli_meta['bytes']==oldcli['file']['size'],
                       'Historical Docker CLI object identity changed')
        hasher=hashlib.sha256()
        with cli.open('rb') as stream:
            for block in iter(lambda:stream.read(1024*1024),b''): hasher.update(block)
        vendor.require(hasher.hexdigest()==oldcli['file']['sha256'] and metadata(cli)==cli_meta,
                       'Historical Docker CLI byte identity changed')
        socket=Path('/var/run/docker.sock'); oldsocket=before['docker_authority']['socket']
        socket_stat=socket.stat()
        vendor.require(str(socket.resolve(strict=True))==oldsocket['realpath'] and
                       stat.S_ISSOCK(socket_stat.st_mode) and
                       socket_stat.st_uid==oldsocket['uid'] and socket_stat.st_gid==oldsocket['gid'] and
                       socket_stat.st_ino==oldsocket['inode'] and
                       socket_stat.st_dev==oldsocket['device'] and socket_stat.st_mode==oldsocket['mode'],
                       'Historical local Docker socket identity changed')
        record['docker_cli_and_socket_match_original']=True
        command=['/usr/bin/docker','--host','unix:///var/run/docker.sock','container','inspect',CID]
        started_ns=time.monotonic_ns()
        record['actions']['docker_called']=True
        completed=subprocess.run(command,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C',
            'PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,timeout=30)
        ended_ns=time.monotonic_ns()
        record['docker_inspect']={'argv':command,'timeout_seconds':30,'started_monotonic_ns':started_ns,
            'ended_monotonic_ns':ended_ns,'returncode':completed.returncode,
            'stdout_bytes':len(completed.stdout),'stdout_sha256':hashlib.sha256(completed.stdout).hexdigest(),
            'stderr_bytes':len(completed.stderr),'stderr_sha256':hashlib.sha256(completed.stderr).hexdigest(),
            'raw_stdout_utf8':completed.stdout.decode('utf-8'),'raw_stderr_utf8':completed.stderr.decode('utf-8'),
            'observed_output_bound_bytes':128*1024}
        vendor.require(completed.returncode==0 and not completed.stderr and len(completed.stdout)<=128*1024,
                       'Actual fresh exact-ID Docker inspect failed or exceeded bound')
        rows=vendor.unique_json(b'{"rows":'+completed.stdout+b'}','actual Docker inspection')['rows']
        vendor.require(isinstance(rows,list) and len(rows)==1 and isinstance(rows[0],dict),'Actual inspection is ambiguous')
        info=rows[0]
        vendor.validate_container(info,config,CID,NONCE,stopped=True)
        vendor.require(all(info['State'].get(k)==v for k,v in values['root_oom_observation']['actual_state'].items()),
                       'Actual terminal state differs from original retained root OOM observation')
        record['actual_terminal_state']=info['State']
        record['exact_original_40gib_full_profile_validated']=True
        record['actual_owned_container_authoritatively_stopped']=True
        record['successful_build']=False
        record['oom_remains_failed_build_not_success']=True
        # Known authenticated cleanup roots only. No traversal, git mutation or cleanup invocation.
        target_rows=[]
        for relative in TARGETS:
            path=config.source/relative
            try: value=metadata(path)
            except FileNotFoundError: value={'path':str(path),'exists':False}
            else: value['exists']=True
            target_rows.append({'relative':relative,'current_lstat_only':value,
                'dl_tracked_markers_must_be_preserved':relative=='vendor/adevtool/dl',
                'current_git_tracked_or_inner_content_not_audited':True})
        record['only_known_regenerable_targets']=target_rows
        record['explicitly_preserved_paths']=['vendor/google_devices/frankel','vendor/state/frankel.json',
             '.repo','out',str(config.work),str(config.cache),str(config.log),str(config.preflight),
             str(config.result),str(config.attempt_lock)]
        vendor.require_source_directory_identities(config,original_ids,source_fd)
        vendor.require(vendor.directory(config.work,uid=os.getuid(),gid=os.getgid())==work,
                       'Workspace identity changed during inspection')
        vendor.require(vendor.capture_regular(config.attempt_lock,64*1024)[1]==current_lock_ref and
                       metadata(config.attempt_lock)==lock_meta,'Attempt-lock changed during inspection')
        record['original_records_unchanged_after_observation']=True
        for name,(path,digest) in INPUTS.items():
            vendor.require(vendor.capture_regular(path,8*1024**2)[1]['sha256']==digest,
                           'Historical record changed during audit: '+name)
        record['status']='actual_g8_exact40_terminal_and_directory_custody_observed_no_cleanup'
    except BaseException as error:
        record['status']='read_only_custody_audit_failed'
        record['failure']={'class':type(error).__name__,'message':str(error)}
    finally:
        if source_fd is not None:
            fcntl.flock(source_fd,fcntl.LOCK_UN)
            os.close(source_fd)
            if 'source_lock' in record: record['source_lock']['released_before_publication']=True
        record['ended_monotonic_ns']=time.monotonic_ns()
        record['ended_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        record['limits']=['Read-only shared flock/identity/state snapshot is released; root must reacquire exclusive original-source lock and current stopped proof before later mutating decision',
            'No original archive rehash/source-wide clean scan/current tracked cache-content audit, no G9 admission or cleanup authorization',
            'OOMtrue/Exit1 remains failure. Exact old40GiB validator is not a profile waiver for new48GiB matcher',
            'Docker stdout/stderr size is checked after bounded30s subprocess capture; no claimed process peak memory bound',
            'Raw JSON and timestamps are emitted by Python with exact integer precision; mode/content hashes are not filesystem immutability']
        print(json.dumps(record,indent=2,sort_keys=True))
    return 0 if record['status'].startswith('actual_g8_exact40') else 2

if __name__=='__main__':
    raise SystemExit(main())
