#!/usr/bin/env python3
"""Exact tiny host-only replay. No Android/Gradle/Docker/VM/signing/repository writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import time

HERE=Path(__file__).resolve().parent
PROPOSAL=Path('/u/elric/tree/wonad-phase1-build-evidence/phase1-ordinary-keyboard-capture-fixture-proposal-20261012-1')
STAGE=Path('/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7')
KOTLIN=STAGE/'external/kotlinc'
JDK=STAGE/'prebuilts/jdk/jdk21/linux-x86'
JUNIT=STAGE/'prebuilts/devtools/tools/lib/junit-4.12.jar'
HAMCREST=STAGE/'prebuilts/devtools/tools/lib/hamcrest-core-1.3.jar'
OUT=HERE/'run'
FROZEN_RECEIPT_SHA='8bbb699c77d822c6a448381a416aa10d06f9fe769ec6a385835c5e5bf32d09b4'
FILES={
 'candidate/android/fixture/src/main/kotlin/org/wonad/fixture/KeyboardCaptureCounters.kt':'220ce93d74624b4b4cf9fcb86657bee2b9e94a1d176c7be36b3ab7ad00c29000',
 'candidate/android/fixture/src/main/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequest.kt':'d991a4fb254cd992d93d052faeebdda84db7e5f1919ba9b69297a66c398966be',
 'candidate/android/fixture/src/test/kotlin/org/wonad/fixture/KeyboardCaptureCountersTest.kt':'c805a243bb9131c3370e41d67c918d21c78358dcb5e8cdd37ff3f5c958916dca',
 'candidate/android/fixture/src/test/kotlin/org/wonad/fixture/PublicKeyboardCaptureRequestTest.kt':'0639417b6c001f5fabdde8907408142eefb0d1c9e50e15a09c6b2007b25d56db',
}

def require(value,message):
    if not value: raise ValueError(message)

def ref(path,maximum=256*1024**2):
    path=Path(path)
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and path.resolve()==path,'Canonical regular input required: '+str(path))
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    def same(a,b):
        return all(getattr(a,k)==getattr(b,k) for k in
          ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        require(same(before,os.fstat(fd)) and 0<before.st_size<=maximum,'Input stat/size changed')
        digest=hashlib.sha256();total=0
        while True:
            chunk=os.read(fd,64*1024)
            if not chunk:break
            digest.update(chunk);total+=len(chunk)
            require(total<=maximum,'Input exceeded bound')
        require(total==before.st_size and same(before,os.fstat(fd)) and same(before,path.lstat()),
                'Input changed during bounded hash')
        return {'path':str(path),'sha256':digest.hexdigest(),'bytes':total}
    finally:os.close(fd)

def source_refs():
    freeze=ref(PROPOSAL/'freeze-review.json',1024**2)
    require(freeze['sha256']==FROZEN_RECEIPT_SHA,'Exact original proposal receipt required')
    sources={name:ref(PROPOSAL/name,1024**2) for name in FILES}
    require(all(sources[name]['sha256']==sha for name,sha in FILES.items()),'Exact frozen pure source/test bytes required')
    return {'proposal_receipt':freeze,'files':sources,'runner':ref(HERE/'PureFixtureJUnitRunner.kt'),
            'helper':ref(__file__)}

def tool_refs():
    # All local Kotlin lib jars are content-bound; no plugins or Android jars
    # are selected for this compile. Hash by streaming, not a large RAM inventory.
    files=[KOTLIN/'bin/kotlinc',JDK/'bin/java',JDK/'release',JDK/'lib/modules',
      JDK/'lib/libjli.so',JDK/'lib/libjava.so',JDK/'lib/libjimage.so',
      JDK/'lib/libzip.so',JDK/'lib/libnio.so',JDK/'lib/libnet.so',
      JDK/'lib/server/libjvm.so',JDK/'conf/security/java.security',JUNIT,HAMCREST]
    jars=sorted((KOTLIN/'lib').glob('*.jar'))
    require(jars and len(jars)<=96,'Unexpected Kotlin jar inventory')
    files.extend(jars)
    require(all(os.access(path,os.X_OK) for path in (KOTLIN/'bin/kotlinc',JDK/'bin/java')),
            'Compiler/Java executable missing')
    return {str(path):ref(path) for path in files}

def expected_cases():
    rows=[]
    for name in FILES:
        if '/src/test/' not in name:continue
        text=(PROPOSAL/name).read_text()
        package=re.findall(r'^package (\S+)$',text,re.M)
        classes=re.findall(r'^class (\w+)\s*\{',text,re.M)
        methods=re.findall(r'@Test\s+fun (\w+)\(',text)
        require(package==['org.wonad.fixture'] and len(classes)==1,'Expected pure JUnit class shape differs')
        rows.extend(package[0]+'.'+classes[0]+'.'+method for method in methods)
    require(len(rows)==len(set(rows))==13,'Exactly13 source-declared JUnit identities required')
    return sorted(rows)

def write_new(path,value):
    with path.open('x') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())

def run(argv,name,env,timeout):
    # Logs are retained even when a compiler/test fails. Only this owned child
    # group is eligible for timeout/interruption cleanup; never any vendor job.
    started=time.time();child=None;error=None;code=None
    stdout=OUT/(name+'.stdout.raw');stderr=OUT/(name+'.stderr.raw')
    with stdout.open('xb') as out,stderr.open('xb') as err:
        try:
            child=subprocess.Popen(argv,cwd=OUT,env=env,stdin=subprocess.DEVNULL,
                stdout=out,stderr=err,start_new_session=True)
            write_new(OUT/(name+'.owned.json'),{'pid':child.pid,'pgid':child.pid,'argv':argv,'started':started})
            code=child.wait(timeout=timeout)
        except BaseException as exc:
            error={'class':type(exc).__name__,'message':str(exc)}
            if child is not None and child.poll() is None:
                os.killpg(child.pid,signal.SIGTERM)
                try:child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
                code=child.returncode
            raise
        finally:
            out.flush();err.flush();os.fsync(out.fileno());os.fsync(err.fileno())
            # Empty raw compiler stderr/stdout are legitimate transcript files,
            # unlike mandatory nonempty source/tool inputs.
            write_new(OUT/(name+'.terminal.json'),{'pid':child.pid if child else None,
                'argv':argv,'started':started,'completed':time.time(),'exit_code':code,'error':error})
    require(type(code) is int and code==0,'Host command failed; preserve raw files: '+name)
    print('PASS host-only '+name+' exit0',flush=True)
    return stdout.read_text()

def execute():
    require(not os.path.lexists(OUT),'Fresh host replay run directory required; never retry/overwrite')
    sources=source_refs();tools=tool_refs();expected=expected_cases()
    cp=':'.join(map(str,(KOTLIN/'lib/kotlin-stdlib.jar',JUNIT,HAMCREST)))
    jar=OUT/'pure-tests.jar'
    compile_argv=[str(KOTLIN/'bin/kotlinc'),'-J-Xmx256m','-J-Xms32m',
        '-jvm-target','17','-no-stdlib','-no-reflect','-classpath',cp,
        *[str(PROPOSAL/name) for name in FILES],str(HERE/'PureFixtureJUnitRunner.kt'),'-d',str(jar)]
    test_argv=[str(JDK/'bin/java'),'-Xmx128m','-Xms16m','-XX:ActiveProcessorCount=1',
              '-cp',str(jar)+':'+cp,'PureFixtureJUnitRunnerKt']
    env={'PATH':str(JDK/'bin')+':/usr/bin:/bin','JAVA_HOME':str(JDK),
         'JAVA_OPTS':'-Xmx256m -Xms32m -XX:ActiveProcessorCount=1',
         'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','HOME':str(OUT),'TMPDIR':str(OUT),
         'PYTHONDONTWRITEBYTECODE':'1'}
    plan={'schema':1,'scope':'pure_host_Kotlin_JUnit_only_no_Android_APK','sources':sources,'tools':tools,
        'expected_cases':expected,'compile_argv':compile_argv,'test_argv':test_argv,'environment':env,
        'compiler_timeout_seconds':60,'test_timeout_seconds':30,
        'compiler_heap_mib':256,'test_heap_mib':128,'junit_version':'4.12',
        'module_gradle_junit_4_13_2_not_exercised':True,'one_logical_processor_each':True,
        'whole_RSS_not_guaranteed_by_heap_flag':True}
    OUT.mkdir(mode=0o700)
    write_new(OUT/'plan.json',plan)
    require(source_refs()==sources and tool_refs()==tools,'Captured sources/tools changed before compiler')
    receipt={'schema':1,'scope':plan['scope'],'status':'failed','plan':ref(OUT/'plan.json'),
             'started':time.time(),'expected_cases':expected,'runtime_qualified':False}
    try:
        run(compile_argv,'compile',env,60)
        text=run(test_argv,'junit',env,30)
        started=re.findall(r'^HOST_CASE_STARTED (\S+)$',text,re.M)
        finished=re.findall(r'^HOST_CASE_FINISHED (\S+)$',text,re.M)
        require(sorted(started)==expected and sorted(finished)==expected and
                len(started)==len(set(started))==13 and len(finished)==len(set(finished))==13,
                'Actual per-case JUnit observations differ from exact source13')
        require(re.findall(r'^HOST_JUNIT_VERSION (.+)$',text,re.M)==['4.12'] and
                re.findall(r'^HOST_RESULT (.+)$',text,re.M)==['run=13 fail=0 ignored=0 assumption=0'] and
                not re.search(r'^HOST_CASE_(?:FAILED|ASSUMPTION|IGNORED) ',text,re.M),
                'Actual JUnit failures/skips/version/count differs')
        require(source_refs()==sources and tool_refs()==tools,'Exact sources/tools changed during replay')
        receipt.update(status='pure_host_compile_and_exact13_junit_pass',actual_started_cases=sorted(started),
            actual_finished_cases=sorted(finished),tests=13,failures=0,errors=0,ignored=0,assumptions=0,
            compiled_jar=ref(jar),sources_and_tools_before_after_identical=True)
    except BaseException as exc:
        receipt['failure']={'class':type(exc).__name__,'message':str(exc)}
        raise
    finally:
        receipt['completed']=time.time()
        write_new(OUT/'receipt.json',receipt)
        print(json.dumps({'receipt':ref(OUT/'receipt.json'),'status':receipt['status']}),flush=True)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    require(args.execute,'Explicit --execute required; no Android/Gradle/Docker mode')
    execute()

if __name__=='__main__':main()
