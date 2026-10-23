#!/usr/bin/python3
"""Compile the Elric successor against retained real framework/Shell inputs.

Historical source/cache stay read-only. This produces class JARs, not an OS or
runtime qualification. Original Binder transaction offsets remain append-only.
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
import xml.etree.ElementTree as ET
import zipfile

from compile_phase0_ui_renewal import CACHE, SOURCE, ref, require
from compile_phase0_phone_task_return import javac_rule

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'android/platform/patches/wonad-shortcut-keyset.patch'
CORE = Path('soong/.intermediates/frameworks/base/services/core/services.core.unboosted/android_common')
SHELL = Path('soong/.intermediates/frameworks/base/libs/WindowManager/Shell/WindowManager-Shell/android_common')


def jar(directory, output):
    with zipfile.ZipFile(output, 'x') as archive:
        for p in sorted(directory.rglob('*.class')):
            archive.write(p, str(p.relative_to(directory)))


def classpath(xml):
    module = ET.parse(xml)
    paths = []
    for node in module.findall('.//classpath'):
        value = node.attrib['path']
        require(value.startswith('/sources/out/'), 'Unknown retained classpath mapping')
        p = CACHE / value.removeprefix('/sources/out/')
        require(p.is_file(), 'Retained classpath missing: ' + str(p)); paths.append(p)
    return module.findall('module')[0].attrib['name'], paths


def aidl_flags():
    for ninja in sorted((CACHE / 'soong').glob('build.sdk_phone64_x86_64.*.ninja')):
        active = False
        with ninja.open() as stream:
            for line in stream:
                if line.startswith('rule '):
                    active = line.startswith('rule m.framework-minus-apex_android_common.aidl')
                if active and 'IWindowManager.aidl' in line and "FLAGS='" in line:
                    flags = shlex.split(re.search(r"FLAGS='([^']*)'", line)[1])
                    return ninja, flags
    raise ValueError('Missing retained framework AIDL compiler rule')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sdk-classes', required=True, type=Path)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.parent == Path('/var/tmp') and output.name.startswith('wonad-elric-glue-') and not output.exists(), 'Fresh private output required')
    require(args.sdk_classes.is_file(), 'Fresh SDK class JAR required')
    output.mkdir(mode=0o700)
    report = dict(schema=1, scope='real_framework_compile_not_runtime_qualification', passed=False, commands=[])
    tracked = {PATCH, Path(__file__).resolve(), args.sdk_classes}
    before = {}
    def track(*paths):
        for p in paths:
            tracked.add(p)
            before.setdefault(str(p), ref(p))
    track(*tracked)
    jdk = SOURCE / 'prebuilts/jdk/jdk21/linux-x86'
    compiler = SOURCE / 'external/kotlinc/bin/kotlinc'
    properties, _ = javac_rule(CACHE / 'soong/build.sdk_phone64_x86_64.9.ninja')
    paths = [CACHE / p.removeprefix('out/') for p in properties['classpath'].removeprefix('-classpath ').split(':')]
    system = CACHE / properties['bootClasspath'].removeprefix('--system=out/')
    peers = CACHE / CORE / 'combined/services.core.unboosted.jar'
    old_kotlin = CACHE / CORE / 'kotlin/services.core.unboosted.jar'
    track(*paths, peers, old_kotlin)
    def execute(label, argv, cwd=None):
        start = time.monotonic()
        with (output / (label + '.log')).open('x') as log:
            result = subprocess.run(list(map(str,argv)), cwd=cwd, env={**os.environ,'JAVA_HOME':str(jdk)}, stdout=log, stderr=log, timeout=300)
        report['commands'].append(dict(label=label,exit_code=result.returncode,argv=list(map(str,argv)),elapsed_seconds=time.monotonic()-start))
        require(result.returncode == 0, label + ' failed; see ' + str(output / (label + '.log')))
    def javac(label, sources, extra):
        target = output / (label + '-classes'); target.mkdir()
        argv = [jdk / 'bin/javac','-J-Xmx3g','-sourcepath','','-g','-XDskipDuplicateBridges=true',
            '-XDstringConcat=inline','-XDturbine.noMethodParameters','-proc:none','-Xlint:-dep-ann',
            '--system=' + str(system),'-classpath',os.pathsep.join(map(str,[*extra,peers,old_kotlin,*paths])),
            '-source','21','-target','21','-d',target,*sources]
        execute(label,argv); jar(target,output / (label + '.jar'))
    try:
        source_root = output / 'source'
        iwm = source_root / 'core/java/android/view/IWindowManager.aidl'
        iwm.parent.mkdir(parents=True)
        original_iwm = SOURCE / 'frameworks/base/core/java/android/view/IWindowManager.aidl'
        track(original_iwm); shutil.copyfile(original_iwm,iwm)
        # The original ProtoLog transform is retained; the patch touches no log.
        srcjar = CACHE / 'soong/.intermediates/frameworks/base/services/core/services.core.protologsrc/android_common/gen/services.core.protolog.srcjar'
        track(srcjar)
        wms = source_root / 'services/core/java/com/android/server/wm/WindowManagerService.java'
        wms.parent.mkdir(parents=True)
        with zipfile.ZipFile(srcjar) as archive:
            wms.write_bytes(archive.read('frameworks/base/services/core/java/com/android/server/wm/WindowManagerService.java'))
        execute('patch-check',['git','apply','--check',PATCH],source_root)
        execute('patch',['git','apply',PATCH],source_root)
        ninja, flags = aidl_flags(); track(ninja)
        rewritten = []
        for flag in flags:
            if flag.startswith('-I'): flag = '-I' + str(SOURCE / flag[2:])
            if flag.startswith('-pout/'): flag = '-p' + str(CACHE / flag[6:])
            rewritten.append(flag)
        generated = output / 'java/android/view/IWindowManager.java'; generated.parent.mkdir(parents=True)
        execute('aidl',[CACHE / 'host/linux-x86/bin/aidl',*rewritten,iwm,generated],SOURCE)
        javac('framework',[generated],[])
        input_sources = []
        for lane in ('input-core/src/main/kotlin','input-integration/src'):
            for p in sorted((ROOT / 'android' / lane).rglob('*.kt')):
                target = source_root / lane / p.relative_to(ROOT / 'android' / lane)
                track(p); target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,target)
                input_sources.append(target)
        track(CACHE / CORE / 'kotlinc-build.xml')
        name, cp = classpath(CACHE / CORE / 'kotlinc-build.xml'); track(*cp)
        execute('input',[compiler,'-J-Xmx3g','-Xjvm-default=all','-Xconsistent-data-class-copy-visibility',
            '-Xsam-conversions=class','-jvm-target','21','-module-name',name,
            '-Xfriend-paths=' + ','.join(map(str,[peers,old_kotlin])),
            '-classpath',os.pathsep.join(map(str,[output / 'framework.jar',peers,*cp])),*input_sources,'-d',output / 'input.jar'])
        javac('wms',[wms],[output / 'input.jar',output / 'framework.jar'])
        broker_sources = []
        for lane in ('broker-core/src/main/kotlin','os-integration/src'):
            for p in sorted((ROOT / 'android' / lane).rglob('*.kt')):
                target = source_root / lane / p.relative_to(ROOT / 'android' / lane)
                track(p); target.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,target)
                broker_sources.append(target)
        signing = SOURCE / 'external/wonad/WonadSigning.kt'; track(signing)
        broker_sources.append(signing)
        track(CACHE / SHELL / 'kotlinc-build.xml')
        name, cp = classpath(CACHE / SHELL / 'kotlinc-build.xml'); track(*cp)
        shell = CACHE / SHELL / 'kotlin/WindowManager-Shell.jar'; track(shell)
        execute('broker',[compiler,'-J-Xmx3g','-Xjvm-default=all','-Xconsistent-data-class-copy-visibility',
            '-Xsam-conversions=class','-jvm-target','21','-module-name',name,'-Xfriend-paths=' + str(shell),
            '-classpath',os.pathsep.join(map(str,[args.sdk_classes,output / 'framework.jar',shell,CACHE / SHELL / 'javac/WindowManager-Shell.jar',*cp])),
            *broker_sources,'-d',output / 'broker.jar'])
        report['passed'] = True
    finally:
        report['inputs_before'] = before
        report['inputs_after'] = {str(p):ref(p) for p in sorted(tracked)}
        report['input_fence_equal'] = before == report['inputs_after']
        report['passed'] = report['passed'] and report['input_fence_equal']
        report['outputs'] = {p.name:ref(p) for p in output.glob('*.jar')}
        (output / 'report.json').write_text(json.dumps(report,indent=2)+'\n')
    require(report['passed'], 'Build inputs changed during compilation')
    print('PASS focused framework/Shell compile: ' + str(output),flush=True)


if __name__ == '__main__': main()
