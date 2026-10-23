#!/usr/bin/python3
"""Compile original/proposed Launcher class against the real pinned build cache.

No mock Android types, source-checkout edits, OS-image changes or promotion.
The original must reproduce every retained TopTaskTracker class byte-for-byte.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
import zipfile

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT.parent/'wonad-grapheneos-2026100600-phase1-custom-11'
CACHE=ROOT.parent/'wonad-grapheneos-x86-phase0-custom11-out-2026100600-6'
REL=Path('quickstep/src/com/android/quickstep/TopTaskTracker.java')
MODULE=Path('soong/.intermediates/packages/apps/Launcher3/Launcher3QuickStepLib/android_common')
PATCH=ROOT/'android/platform/patches/wonad-recents-display-task-cache.patch'
ORIGINAL_SHA='153de2f4898e8f90ef837b98682152c01124f3028760f49a0319d4a68de1aecc'


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def java_properties(ninja):
    marker='out/'+str(MODULE/'javac/Launcher3QuickStepLib.jar')+' $'
    lines=[];active=False
    with ninja.open() as stream:
        for line in stream:
            if not active:
                if line.strip()==marker:active=True
                else:continue
            elif line.startswith('build '):break
            lines.append(line)
    if not lines:raise ValueError('Missing exact retained Launcher javac rule')
    properties={}
    for line in lines:
        match=re.match(r'    ([A-Za-z]+) = (.*)\n$',line)
        if match:properties[match[1]]=match[2]
    assert properties['javaVersion']=='21' and properties['processor']=='-proc:none'
    assert properties['bootClasspath'].startswith('--system=out/') and properties['classpath'].startswith('-classpath out/')
    return properties,''.join(lines)


def run(output):
    assert output.is_absolute() and output.parent==Path('/tmp') and not output.exists() and not output.is_symlink()
    original=SOURCE/'packages/apps/Launcher3'/REL
    assert sha(original)==ORIGINAL_SHA
    ninja=CACHE/'soong/build.sdk_phone64_x86_64.1.ninja'
    properties,rule=java_properties(ninja)
    classpath=[CACHE/p.removeprefix('out/') for p in properties['classpath'].removeprefix('-classpath ').split(':')]
    assert classpath and all(p.is_file() for p in classpath)
    compiled=CACHE/MODULE/'javac/Launcher3QuickStepLib.jar'
    kotlin=CACHE/MODULE/'kotlin/Launcher3QuickStepLib.jar'
    system=CACHE/properties['bootClasspath'].removeprefix('--system=out/')
    jdk=SOURCE/'prebuilts/jdk/jdk21/linux-x86'
    inputs={Path(__file__).resolve(),PATCH,original,ninja,CACHE/'soong/build.sdk_phone64_x86_64.ninja',
            compiled,kotlin,jdk/'bin/javac',jdk/'bin/java',jdk/'lib/modules',jdk/'lib/server/libjvm.so',
            *classpath,*(p for p in system.rglob('*') if p.is_file())}
    before={str(p):dict(sha256=sha(p),bytes=p.stat().st_size) for p in sorted(inputs)}
    output.mkdir(mode=0o700)
    (output/'retained-javac-rule.txt').write_text(rule)
    shutil.copyfile(PATCH,output/PATCH.name)
    shutil.copyfile(Path(__file__).resolve(),output/'runner.py')
    report=dict(schema=1,scope='real_pinned_Launcher_class_compile_not_OS_or_runtime_qualification',
                source_checkout_modified=False,cache_modified=False,runtime_qualified=False,commands=[])
    try:
        for label in ('original','corrected'):
            work=output/label
            source=work/REL;source.parent.mkdir(parents=True)
            shutil.copyfile(original,source)
            if label=='corrected':
                subprocess.run(['git','apply','--check',str(output/PATCH.name)],cwd=work,check=True)
                subprocess.run(['git','apply',str(output/PATCH.name)],cwd=work,check=True)
            classes=work/'classes';classes.mkdir()
            # Prepend retained full Java/Kotlin peer bodies to preserve package-
            # private signatures; the sole changed class itself is source input.
            argv=[str(jdk/'bin/javac'),'-J-Xmx2048M','-J-XX:CICompilerCount=6',
                '-J-XX:+UseDynamicNumberOfGCThreads','-J-XX:+TieredCompilation','-J-XX:TieredStopAtLevel=1',
                '-Xmaxerrs','9999999','-encoding','UTF-8','-sourcepath','','-g',
                '-XDskipDuplicateBridges=true','-XDstringConcat=inline','-XDturbine.noMethodParameters',
                '-proc:none','-Xlint:-dep-ann','--system='+str(system),'-classpath',
                os.pathsep.join(map(str,[compiled,kotlin,*classpath])),
                '-source','21','-target','21','-d',str(classes),str(source)]
            started=time.monotonic()
            with (work/'compiler.log').open('x') as log:
                result=subprocess.run(argv,stdout=log,stderr=log,timeout=120)
            report['commands'].append(dict(label=label,argv=argv,exit_code=result.returncode,
                elapsed_seconds=time.monotonic()-started,source_sha256=sha(source),log_sha256=sha(work/'compiler.log')))
            assert result.returncode==0, label+' real-framework compile failed; retain compiler.log'
            actual={str(p.relative_to(classes)):p.read_bytes() for p in classes.rglob('*.class')}
            assert actual and all(re.fullmatch(r'com/android/quickstep/TopTaskTracker(?:\$[^/]+)?\.class',n) for n in actual)
            with zipfile.ZipFile(compiled) as archive:
                expected={n:archive.read(n) for n in archive.namelist() if
                    re.fullmatch(r'com/android/quickstep/TopTaskTracker(?:\$[^/]+)?\.class',n)}
            assert actual.keys()==expected.keys(), 'Compiled class-family membership differs'
            equal=[n for n in actual if actual[n]==expected[n]]
            report[label]=dict(classes={n:hashlib.sha256(b).hexdigest() for n,b in actual.items()},
                byte_exact_control_classes=equal,changed_classes=sorted(set(actual)-set(equal)))
            if label=='original':assert actual==expected, 'Original class bytes did not reproduce; inspect before packaging'
            else:assert report[label]['changed_classes'], 'Proposal did not change any class'
        report['status']='passed_original_and_corrected_real_framework_compile'
    except BaseException as error:
        report.update(status='not_passed',error=repr(error));raise
    finally:
        after={str(p):dict(sha256=sha(p),bytes=p.stat().st_size) for p in sorted(inputs)}
        report.update(inputs_before=before,inputs_after=after,input_fence_equal=before==after)
        if before!=after:report['status']='not_passed'
        (output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    assert report['input_fence_equal']
    print(json.dumps({k:report[k] for k in ('status','input_fence_equal','original','corrected')},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
