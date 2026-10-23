/usr/bin/python3 -B - <<'PY'
import copy,datetime,hashlib,json,re,shlex,subprocess,sys,time,types
from pathlib import Path
ROOT=Path('/u/elric/tree/wonad')
E=Path('/u/elric/tree/wonad-phase1-build-evidence')
CID='0ab59047b27abe8b92ad754844c1c97e6a0b1db0f287654ebbd763eabf91095c'
NONCE='1a50fd5e32be04c99bc51e19ed71c3962330fe2a4132b4bd9d38570b393a725a'
record={'schema':1,'scope':'read-only exactG9 inspection+cgroup snapshot; NOT build success/sourcefreeze/runtime qualification','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'started_monotonic_ns':time.monotonic_ns(),'container_id':CID,'container_name':'wonad-phase1-frankel-vendor-2026100600-009','expected_nonce':NONCE,'no_root_pty_handle_polled':True,'no_container_or_source_mutation':True}
try:
 helper=ROOT/'android/tools/run_frankel_vendor.py'; raw=helper.read_bytes()
 if hashlib.sha256(raw).hexdigest()!='bf2e9ff0a1f71a0586038245e646865f3ea4fc25bbc0fdebb1cf54e6eb721d4b': raise ValueError('current helper identity changed')
 v=types.ModuleType('g9_monitor_bound_validator');v.__file__=str(helper);sys.modules[v.__name__]=v
 exec(compile(raw,str(helper),'exec'),v.__dict__)
 bridge=E/'prepare-phase1-frankel-vendor-cache-20261012-9.sh';b=bridge.read_bytes()
 if hashlib.sha256(b).hexdigest()!='3dbea9385949b39e34e3078487ff171c4b08393d491953f78c3a0f7cfda716c2':raise ValueError('G9 bridge identity changed')
 invocation=shlex.split(b.decode().split('\nexec ',1)[1].replace('\\\n',''))
 config=v.config_from_args(v.build_parser().parse_args(['--check-only',*invocation[4:]]))
 pre_raw,pre_ref=v.capture_regular(config.preflight,128*1024)
 pre=v.unique_json(pre_raw,'actualG9preflight')
 if pre['nonce']!=NONCE or pre['create_argv']!=v.create_command(config,NONCE):raise ValueError('G9 preflight config/nonce differs')
 record['actual_preflight']=pre_ref
 command=['/usr/bin/docker','--host','unix:///var/run/docker.sock','container','inspect',CID]
 start=time.monotonic_ns()
 out=subprocess.run(command,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},capture_output=True,timeout=5)
 record['docker_inspect']={'argv':command,'started_monotonic_ns':start,'ended_monotonic_ns':time.monotonic_ns(),'returncode':out.returncode,'raw_stdout_utf8':out.stdout.decode(),'raw_stderr_utf8':out.stderr.decode(),'bytes':len(out.stdout),'sha256':hashlib.sha256(out.stdout).hexdigest()}
 if out.returncode or out.stderr or len(out.stdout)>128*1024:raise ValueError('actual bounded exactID inspect failed')
 rows=v.unique_json(b'{"rows":'+out.stdout+b'}','G9inspect')['rows']
 if not isinstance(rows,list) or len(rows)!=1:raise ValueError('inspect ambiguity')
 info=rows[0]; actual_state=info['State']
 # State-only neutral projection calls the exact existing non-state profile checks.
 # It is explicitly NOT a claim this Running observation was a Created observation.
 neutral=copy.deepcopy(info)
 neutral['State']={'Status':'created','Running':False,'Paused':False,'Restarting':False,'Dead':False,'OOMKilled':False,'Pid':0,'ExitCode':0,'StartedAt':'0001-01-01T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z'}
 v.validate_container(neutral,config,CID,NONCE,stopped=False)
 record['profile_check']='Actual immutable identity/config/mount/authority fields pass exactbf2e9 validator via explicitly synthetic CREATED state-only projection; actual state independently retained below'
 record['actual_state']=actual_state
 record['created_utc']=info['Created']
 record['profile_summary']={'image':info['Image'],'user':info['Config']['User'],'memory_bytes':info['HostConfig']['Memory'],'memory_swap_bytes':info['HostConfig']['MemorySwap'],'cpuset':info['HostConfig']['CpusetCpus'],'nano_cpus':info['HostConfig']['NanoCpus'],'pids':info['HostConfig']['PidsLimit'],'rootfs_read_only':info['HostConfig']['ReadonlyRootfs'],'binds':info['HostConfig']['Binds'],'tmpfs':info['HostConfig']['Tmpfs']}
 if actual_state['Running'] is True:
  if actual_state['Status']!='running' or type(actual_state['Pid']) is not int or actual_state['Pid']<=0:raise ValueError('malformedRunning state')
  proc=Path('/proc')/str(actual_state['Pid'])/'cgroup'
  cgraw=proc.read_text(encoding='ascii')
  expected='/system.slice/docker-'+CID+'.scope'
  if cgraw!='0::'+expected+'\n':raise ValueError('PID cgroup notexact ownedCID')
  cg=Path('/sys/fs/cgroup')/expected.lstrip('/')
  counters={}
  raws={}
  for name in ('memory.current','memory.peak','memory.max','memory.swap.max','memory.events','cpu.max','cpuset.cpus.effective'):
   data=(cg/name).read_bytes()
   if not 0<len(data)<=4096:raise ValueError('cgroup observation size differs')
   text=data.decode('ascii').strip()
   raws[name]={'raw_ascii':data.decode('ascii'),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
   if name=='memory.events':
    values={}
    for line in text.splitlines():
     pair=line.split()
     if len(pair)!=2 or pair[0] in values or not re.fullmatch('[0-9]+',pair[1]):raise ValueError('malformedcgroup events')
     values[pair[0]]=int(pair[1])
    counters[name]=values
   elif name.startswith('memory.'):
    if not re.fullmatch('[0-9]+',text):raise ValueError('nonnumericmemory')
    counters[name]=int(text)
   else:counters[name]=text
  if counters['memory.max']!=48*1024**3 or counters['memory.swap.max']!=0 or counters['cpu.max']!='400000 100000' or counters['cpuset.cpus.effective']!='0-3':raise ValueError('actualcgroup cap differs')
  record['cgroup']={'path':str(cg),'proc_cgroup_raw':cgraw,'counters':counters,'raw_records':raws,'non_atomic_read_snapshot':True,'no_peak_reset_or_event_write':True}
 elif actual_state['Status']=='exited':
  v.validate_container(info,config,CID,NONCE,stopped=True)
  record['cgroup']={'unavailable_after_terminal':'No cgroup read/peak reconstruction attempted; earlier records retained'}
 else:
  record['cgroup']={'not_currently_running':True}
 record['status']='observed_exactG9_state_profile_and_cgroup'
except BaseException as error:
 record['status']='read_only_monitor_observation_failed'
 record['failure']={'class':type(error).__name__,'message':str(error)}
record['ended_monotonic_ns']=time.monotonic_ns()
print(json.dumps(record,sort_keys=True,indent=2))
PY
