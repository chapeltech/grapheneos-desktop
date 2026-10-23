#!/usr/bin/python3
"""Compile Task's phone-return hook against the pinned real services cache.

The original transformed ProtoLog source must reproduce its complete retained
class family. Only the three-line hook is applied to a disposable source copy;
the historical checkout/cache remain read-only. This is not runtime evidence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import zipfile

from compile_phase0_ui_renewal import CACHE, SOURCE, ref, require

ROOT = Path(__file__).resolve().parents[2]
MODULE = Path('soong/.intermediates/frameworks/base/services/core/services.core.unboosted/android_common')
RELATIVE = Path('services/core/java/com/android/server/wm/Task.java')
PATCH = ROOT / 'android/platform/patches/wonad-native-phone-task-return.patch'
ORIGINAL = SOURCE / 'frameworks/base' / RELATIVE
ORIGINAL_SHA = 'b58a4e7a8b9dba792c81e60a82e799aac81cd5f22175d6eb633f3c404153f6f8'
FAMILY = re.compile(r'com/android/server/wm/Task(?:\$[^/]+)?\.class')


def javac_rule(ninja):
    marker = 'out/' + str(MODULE / 'javac/services.core.unboosted.jar47') + ' $'
    lines = []
    active = False
    with ninja.open() as stream:
        for line in stream:
            if not active:
                if line.strip() != marker:
                    continue
                active = True
            elif line.startswith('build '):
                break
            lines.append(line)
    require(lines, 'Exact retained Task javac rule required')
    properties = {}
    for line in lines:
        match = re.fullmatch(r'    ([A-Za-z]+) = (.*)\n', line)
        if match:
            properties[match[1]] = match[2]
    require(properties.get('javaVersion') == '21' and properties.get('processor') == '-proc:none',
            'Unexpected retained javac configuration')
    return properties, ''.join(lines)


def run(output, compiled):
    require(output.is_absolute() and output.parent == Path('/tmp') and
            output.name.startswith('wonad-phase0-phone-task-compile-') and
            not output.exists() and not output.is_symlink(), 'Fresh private literal /tmp output required')
    require(compiled.is_absolute() and compiled.resolve(strict=True) == compiled,
            'Literal Kotlin compilation directory required')
    kotlin_report = json.loads((compiled / 'report.json').read_text())
    require(kotlin_report['status'] == 'passed_focused_original_and_corrected_compile' and
            kotlin_report['input_fence_equal'], 'Complete real-framework Kotlin compile required')
    require(ref(ORIGINAL)['sha256'] == ORIGINAL_SHA, 'Retained Task source differs')
    ninja = CACHE / 'soong/build.sdk_phone64_x86_64.9.ninja'
    properties, rule = javac_rule(ninja)
    classpath = [CACHE / p.removeprefix('out/') for p in
                 properties['classpath'].removeprefix('-classpath ').split(':')]
    require(classpath and all(p.is_file() for p in classpath), 'Complete real framework classpath required')
    system = CACHE / properties['bootClasspath'].removeprefix('--system=out/')
    srcjar = CACHE / 'soong/.intermediates/frameworks/base/services/core/services.core.protologsrc/android_common/gen/services.core.protolog.srcjar'
    peers = CACHE / MODULE / 'combined/services.core.unboosted.jar'
    kotlin = CACHE / MODULE / 'kotlin/services.core.unboosted.jar'
    java_cache = CACHE / MODULE / 'javac/services.core.unboosted.jar47'
    jdk = SOURCE / 'prebuilts/jdk/jdk21/linux-x86'
    source_name = 'frameworks/base/' + str(RELATIVE)
    with zipfile.ZipFile(srcjar) as archive:
        generated = archive.read(source_name)
    with zipfile.ZipFile(java_cache) as archive:
        expected = {n: archive.read(n) for n in archive.namelist() if FAMILY.fullmatch(n)}
    require(len(expected) == 6, 'Exact original six-class Task family required')
    inputs = {Path(__file__).resolve(), PATCH, ORIGINAL, ninja, srcjar, peers, kotlin, java_cache,
              compiled / 'report.json', compiled / 'original/ui.jar', compiled / 'corrected/ui.jar',
              jdk / 'bin/javac', jdk / 'bin/java', jdk / 'lib/modules', jdk / 'lib/server/libjvm.so',
              *classpath, *(p for p in system.rglob('*') if p.is_file())}
    for name in ('WonadUiBridge.kt', 'WonadNativeBridge.kt'):
        source = ROOT / 'android/input-integration/src/com/android/server/wm' / name
        require(ref(source) == ref(compiled / 'corrected' / name), 'Compiled bridge source changed')
        inputs.add(source)
    before = {str(p): ref(p) for p in sorted(inputs)}
    output.mkdir(mode=0o700)
    shutil.copyfile(PATCH, output / PATCH.name)
    (output / 'retained-javac-rule.txt').write_text(rule)
    report = dict(schema=1, scope='real_pinned_Task_compile_not_OS_or_runtime_qualification',
                  runtime_qualified=False, image_built=False, source_checkout_modified=False,
                  cache_modified=False, commands=[], inputs_before=before)
    try:
        for label in ('original', 'corrected'):
            work = output / label
            source = work / RELATIVE
            source.parent.mkdir(parents=True)
            source.write_bytes(generated)
            # Apply the same hook to untransformed source as a context/control
            # check; no changed line contains a ProtoLog invocation.
            plain = work / 'untransformed' / RELATIVE
            plain.parent.mkdir(parents=True)
            shutil.copyfile(ORIGINAL, plain)
            if label == 'corrected':
                for directory in (work, work / 'untransformed'):
                    subprocess.run(['git', 'apply', '--check', str(PATCH)], cwd=directory, check=True)
                    subprocess.run(['git', 'apply', str(PATCH)], cwd=directory, check=True)
            classes = work / 'classes'
            classes.mkdir()
            bridge = compiled / label / 'ui.jar'
            argv = [str(jdk / 'bin/javac'), '-J-Xmx2048M', '-J-XX:CICompilerCount=6',
                    '-J-XX:+UseDynamicNumberOfGCThreads', '-J-XX:+TieredCompilation',
                    '-J-XX:TieredStopAtLevel=1', '-Xmaxerrs', '9999999', '-encoding', 'UTF-8',
                    '-sourcepath', '', '-g', '-XDskipDuplicateBridges=true', '-XDstringConcat=inline',
                    '-XDturbine.noMethodParameters', '-proc:none', '-Xlint:-dep-ann',
                    '--system=' + str(system), '-classpath',
                    os.pathsep.join(map(str, [bridge, peers, kotlin, *classpath])),
                    '-source', '21', '-target', '21', '-d', str(classes), str(source)]
            started = time.monotonic()
            with (work / 'compiler.log').open('x') as log:
                result = subprocess.run(argv, stdout=log, stderr=log, timeout=180)
            report['commands'].append(dict(label=label, argv=argv, exit_code=result.returncode,
                elapsed_seconds=time.monotonic() - started, source=ref(source), log=ref(work / 'compiler.log')))
            require(result.returncode == 0, label + ' Task compile failed; retain compiler.log')
            actual = {str(p.relative_to(classes)): p.read_bytes() for p in classes.rglob('*.class')}
            require(actual.keys() == expected.keys(), 'Task class family membership differs')
            equal = sorted(n for n in actual if actual[n] == expected[n])
            report[label] = dict(byte_exact_control_classes=equal,
                                 changed_classes=sorted(set(actual) - set(equal)))
            with zipfile.ZipFile(work / 'task.jar', 'x') as archive:
                for n in sorted(actual):
                    archive.writestr(n, actual[n])
            report[label]['jar'] = ref(work / 'task.jar')
            if label == 'original':
                require(actual == expected, 'Original Task did not reproduce retained class bytes')
            else:
                require(report[label]['changed_classes'], 'Hook did not change compiled Task')
        report['status'] = 'passed_original_and_corrected_real_framework_compile'
    except BaseException as error:
        report.update(status='not_passed', error=repr(error))
        raise
    finally:
        report['inputs_after'] = {str(p): ref(p) for p in sorted(inputs)}
        report['input_fence_equal'] = report['inputs_before'] == report['inputs_after']
        if not report['input_fence_equal']:
            report['status'] = 'not_passed'
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    require(report['input_fence_equal'], 'Retained framework or sources changed')
    return {k: report[k] for k in ('status', 'original', 'corrected', 'input_fence_equal')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiled', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.compiled), indent=2))
