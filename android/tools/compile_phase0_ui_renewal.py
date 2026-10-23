#!/usr/bin/python3
"""Focused real-framework compilation, never an OS image/runtime qualification.

Read the retained source-matched services cache without changing it. Compile the
original and corrected UI/native bridges against their framework classpath and keep
all command outputs and input identities in a new private /tmp directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / 'wonad-grapheneos-2026100600-phase1-custom-11'
CACHE = ROOT.parent / 'wonad-grapheneos-x86-phase0-custom11-out-2026100600-6'
RELATIVE = Path('input-integration/src/com/android/server/wm/WonadUiBridge.kt')
ORIGINAL_SHA = 'f3255791a17f750e988794fc7f0a4f37c83cbe7155612cd4620200698231e566'
NATIVE_RELATIVE = RELATIVE.with_name('WonadNativeBridge.kt')
ORIGINAL_NATIVE_SHA = '44aec6236fcd41610c4e6c708ca94087835e96bba500eb26a5df15f51bbfb775'
SERVICES_SHA = '71d90aa573a54550d3f274d6d235b2828c2064ff90536f75cd4bdcd7217bb2dd'
COMBINED_SHA = 'e29f3cb674700f661ecf3b5130f98cffa130a6266b8bb3e40b461cccc5d0be4c'
KOTLIN_SHA = 'cea2766c3400afba3812552e917746d6b0e5f74091518acf8d60515fbf23d39a'


def require(value, message):
    if not value:
        raise ValueError(message)


def ref(path):
    info = path.stat()
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    def stable(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
                value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(stable(path.stat()) == stable(info), 'Input changed while hashing: ' + str(path))
    return {'sha256': digest, 'bytes': info.st_size}


def run(output):
    require(output.is_absolute() and output.parent == Path('/tmp') and
            output.name.startswith('wonad-phase0-ui-renewal-compile-') and
            not output.exists() and not output.is_symlink(), 'Fresh literal private /tmp output required')
    module = CACHE / 'soong/.intermediates/frameworks/base/services/core/services.core.unboosted/android_common'
    xml = module / 'kotlinc-build.xml'
    tree = ET.parse(xml)
    entries = tree.findall('module')
    require(len(entries) == 1, 'Exactly one retained Kotlin module required')
    module_name = entries[0].attrib['name']
    require(module_name == 'frameworks__base__services__core__android_common__services.core.unboosted',
            'Unexpected services compiler module')
    classpath = []
    for node in tree.findall('.//classpath'):
        name = node.attrib['path']
        require(name.startswith('/sources/out/'), 'Unexpected retained classpath path')
        classpath.append(CACHE / name.removeprefix('/sources/out/'))
    require(len(classpath) == 225 and all(p.is_file() for p in classpath), 'Complete real framework classpath required')
    combined = module / 'combined/services.core.unboosted.jar'
    kotlin = module / 'kotlin/services.core.unboosted.jar'
    services = CACHE / 'target/product/emu64x/system/framework/services.jar'
    original = SOURCE / 'external/wonad' / RELATIVE
    current = ROOT / 'android' / RELATIVE
    original_native = SOURCE / 'external/wonad' / NATIVE_RELATIVE
    current_native = ROOT / 'android' / NATIVE_RELATIVE
    jdk = SOURCE / 'prebuilts/jdk/jdk21/linux-x86'
    compiler = SOURCE / 'external/kotlinc/bin/kotlinc'
    for path, pin in ((combined, COMBINED_SHA), (kotlin, KOTLIN_SHA),
                      (services, SERVICES_SHA), (original, ORIGINAL_SHA),
                      (original_native, ORIGINAL_NATIVE_SHA)):
        require(ref(path)['sha256'] == pin, 'Retained baseline differs: ' + str(path))
    paths = {Path(__file__).resolve(), original, current, original_native, current_native,
             xml, services, combined, kotlin, compiler,
             SOURCE / 'external/kotlinc/lib/kotlin-compiler.jar', jdk / 'bin/java',
             SOURCE / 'external/wonad/.wonad-stage.json', *classpath}
    before = {str(p): ref(p) for p in sorted(paths)}
    require(before[str(original)] != before[str(current)], 'No distinct correction to compile')
    output.mkdir(mode=0o700)
    report = {'schema': 1, 'scope': 'focused_real_pinned_framework_compile_not_OS_or_runtime_qualification',
              'cache_read_only': True, 'historical_stage_modified': False,
              'image_built': False, 'runtime_qualified': False, 'commands': [], 'inputs_before': before}
    try:
        for name, sources in (('original', (original, original_native)),
                              ('corrected', (current, current_native))):
            directory = output / name; directory.mkdir(mode=0o700)
            snapshots = []
            for source in sources:
                snapshot = directory / source.name; snapshot.write_bytes(source.read_bytes())
                snapshots.append(snapshot)
            argv = [str(compiler), '-J-Xmx2048M', '-Xjvm-default=all',
                    '-Xsuppress-version-warnings', '-Xconsistent-data-class-copy-visibility',
                    '-Xsam-conversions=class', '-jvm-target', '21', '-module-name', module_name,
                    '-Xfriend-paths=' + ','.join(map(str, (combined, kotlin))), '-classpath',
                    os.pathsep.join(map(str, [combined, *classpath])), *map(str, snapshots),
                    '-d', str(directory / 'ui.jar')]
            started = time.monotonic()
            with (directory / 'compiler.log').open('x') as log:
                result = subprocess.run(argv, env={**os.environ, 'JAVA_HOME': str(jdk)},
                                        stdout=log, stderr=subprocess.STDOUT, timeout=180)
            report['commands'].append({'label': name, 'argv': argv, 'exit_code': result.returncode,
                                       'elapsed_seconds': time.monotonic() - started,
                                       'log': ref(directory / 'compiler.log'),
                                       'sources': {p.name: ref(p) for p in snapshots}})
            require(result.returncode == 0, name + ' actual framework compile failed; see compiler.log')
            report[name + '_jar'] = ref(directory / 'ui.jar')
        report['status'] = 'passed_focused_original_and_corrected_compile'
    except BaseException as error:
        report['status'] = 'not_passed'; report['error'] = repr(error)
        raise
    finally:
        report['inputs_after'] = {str(p): ref(p) for p in sorted(paths)}
        report['input_fence_equal'] = report['inputs_before'] == report['inputs_after']
        if not report['input_fence_equal']:
            report['status'] = 'not_passed'
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    require(report['input_fence_equal'], 'Source or retained framework cache changed')
    return {'status': report['status'], 'report': str(output / 'report.json'),
            'image_built': False, 'runtime_qualified': False}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(run(parser.parse_args().output), indent=2))
