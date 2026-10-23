#!/usr/bin/python3
"""Reproduce the selected SystemUI broker, then compile its hotplug correction.

Uses the retained real framework classpath read-only. This is an incremental
development build, not OS/runtime qualification or a substitute for one.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / 'wonad-grapheneos-2026100600-phase1-custom-11'
CACHE = ROOT.parent / 'wonad-grapheneos-x86-phase0-custom11-out-2026100600-6'
PRIOR = Path('/var/tmp/wonad-autostart.nvtVNSDk')
CONTROLLER = Path('os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt')
PREFIX = 'org/wonad/desktop/broker/'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def run(output):
    require(output.is_absolute() and output.parent == Path('/tmp') and
            output.name.startswith('wonad-phase0-lease-renewal-compile-') and
            not output.exists() and not output.is_symlink(), 'Fresh private /tmp output required')
    freeze = PRIOR / 'source-freeze.json'
    require(sha(freeze) == '04330cf79b927ee5cf1005aba3a947e46bde30fcdf5c637f8d30e731a050871c',
            'Selected image source freeze differs')
    require(sha(PRIOR / 'broker.jar') == 'd5fedf631d91ebc5c9220de214b9bf4ef123bd1f8d5529338624270a1028d61b',
            'Original compiled broker differs')
    require(sha(PRIOR / 'SystemUI.apk') == '0206ce64a6d3513d5c4fa692de26642cbffca7c98c5c91b4e211f4a10684296c',
            'Selected SystemUI differs')
    frozen = json.loads(freeze.read_text())
    names = sorted(Path(name.removeprefix('broker/')) for name in frozen if
                   name == 'broker/WonadSigning.kt' or name.endswith('.kt') and
                   name.startswith(('broker/broker-core/src/main/kotlin/', 'broker/os-integration/src/')))
    require(len(names) == 14 and CONTROLLER in names, 'Exact original broker source closure required')
    original = {name: PRIOR / 'broker' / name for name in names}
    corrected = {name: path if name == Path('WonadSigning.kt') else ROOT / 'android' / name
                 for name, path in original.items()}
    for name, path in original.items():
        require(not path.is_symlink() and sha(path) == frozen['broker/' + str(name)],
                'Original source differs: ' + str(name))
        if name != CONTROLLER:
            require(sha(path) == sha(corrected[name]), 'Unrelated source delta: ' + str(name))
    require(sha(original[CONTROLLER]) == '67e6e7c96eefb9d33db54494b571a5d037a3efd49b7dc80d562637cfb98e16ca',
            'Original controller is not the selected image source')
    require(sha(corrected[CONTROLLER]) != sha(original[CONTROLLER]), 'No correction to compile')
    module = CACHE / 'soong/.intermediates/frameworks/base/packages/SystemUI/SystemUI-core/android_common'
    xml = module / 'kotlinc-build.xml'
    tree = ET.parse(xml)
    classpath = []
    for node in tree.findall('.//classpath'):
        path = node.attrib['path']
        require(path.startswith('/sources/out/'), 'Unexpected real framework classpath')
        classpath.append(CACHE / path.removeprefix('/sources/out/'))
    kotlin = module / 'kotlin/SystemUI-core.jar'
    classpath += [kotlin, module / 'javac/SystemUI-core.jar']
    require(len(classpath) == 751 and all(p.is_file() for p in classpath), 'Incomplete real SystemUI classpath')
    jdk = SOURCE / 'prebuilts/jdk/jdk21/linux-x86'
    compiler = SOURCE / 'external/kotlinc/bin/kotlinc'
    inputs = {Path(__file__).resolve(), freeze, PRIOR / 'broker.jar', PRIOR / 'SystemUI.apk',
              xml, compiler, SOURCE / 'external/kotlinc/lib/kotlin-compiler.jar', jdk / 'bin/java',
              SOURCE / 'external/wonad/.wonad-stage.json', *classpath, *original.values(), *corrected.values()}
    before = {str(p): sha(p) for p in sorted(inputs)}
    output.mkdir(mode=0o700)
    report = dict(schema=1, scope='real_framework_incremental_compile_not_OS_or_runtime_qualification',
                  selected_systemui_sha256=sha(PRIOR / 'SystemUI.apk'), commands=[],
                  retained_cache_read_only=True, historical_stage_modified=False,
                  image_built=False, runtime_qualified=False, inputs_before=before)
    try:
        for label, files in (('original', original), ('corrected', corrected)):
            directory = output / label
            directory.mkdir(mode=0o700)
            snapshots = []
            for name, path in files.items():
                snapshot = directory / name
                snapshot.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, snapshot)
                snapshots.append(snapshot)
            # Preserve the exact original focused compilation flags, including
            # its default Kotlin module name; do not silently recompile peers
            # with different internal-name mangling.
            argv = [str(compiler), '-J-Xmx2048M', '-Xjvm-default=all',
                    '-Xconsistent-data-class-copy-visibility', '-Xsam-conversions=class',
                    '-jvm-target', '21', '-Xfriend-paths=' + str(kotlin),
                    '-classpath', os.pathsep.join(map(str, classpath)),
                    *map(str, snapshots), '-d', str(directory / 'broker.jar')]
            # The real SystemUI classpath exceeds Linux's per-argument limit
            # after absolute host-path expansion. Kotlin's response file keeps
            # the same compiler options without relying on shell expansion.
            response = directory / 'compiler.args'
            response.write_text('\n'.join('"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'
                                           for value in argv[2:]) + '\n')
            command = [argv[0], argv[1], '@' + str(response)]
            started = time.monotonic()
            with (directory / 'compiler.log').open('x') as log:
                result = subprocess.run(command, env={**os.environ, 'JAVA_HOME': str(jdk)},
                                        stdout=log, stderr=subprocess.STDOUT, timeout=180)
            report['commands'].append(dict(label=label, argv=argv, command=command, exit_code=result.returncode,
                elapsed_seconds=time.monotonic() - started, log_sha256=sha(directory / 'compiler.log')))
            require(result.returncode == 0, label + ' compile failed; see compiler.log')
        def classes(path):
            with zipfile.ZipFile(path) as jar:
                return {n: jar.read(n) for n in jar.namelist() if n.startswith(PREFIX) and n.endswith('.class')}
        prior_classes = classes(PRIOR / 'broker.jar')
        rebuilt = classes(output / 'original/broker.jar')
        require(rebuilt and rebuilt == prior_classes, 'Original compile failed byte-exact class control')
        report['original_byte_exact_classes'] = len(rebuilt)
        new = classes(output / 'corrected/broker.jar')
        unrelated = lambda data: {n: b for n, b in data.items() if not n.startswith(PREFIX + 'NativeDesktopController')}
        require(unrelated(new) == unrelated(rebuilt), 'Unrelated broker classes changed')
        report['unrelated_byte_exact_classes'] = len(unrelated(new))
        report['original_jar_sha256'] = sha(output / 'original/broker.jar')
        report['corrected_jar_sha256'] = sha(output / 'corrected/broker.jar')
        report['corrected_controller_sha256'] = sha(corrected[CONTROLLER])
        report['status'] = 'passed_real_framework_compile_and_exact_original_control'
    except BaseException as error:
        report.update(status='not_passed', error=repr(error))
        raise
    finally:
        report['inputs_after'] = {str(p): sha(p) for p in sorted(inputs)}
        report['input_fence_equal'] = before == report['inputs_after']
        if not report['input_fence_equal']:
            report['status'] = 'not_passed'
        (output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    require(report['input_fence_equal'], 'Retained source/framework input changed')
    return {key: report[key] for key in ('status', 'original_byte_exact_classes',
                                        'unrelated_byte_exact_classes', 'corrected_jar_sha256')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    print(json.dumps(run(parser.parse_args().output), indent=2))
