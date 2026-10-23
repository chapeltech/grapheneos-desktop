#!/usr/bin/env python3
"""Compile the staged broker against real pinned framework/Shell classpaths.

This avoids whole-Shell annotation processing for a focused compile check. It
does not rebuild SystemUI or produce/install an OS, and is not runtime evidence.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve(strict=True)
    stage = source / 'external/wonad'
    metadata = json.loads((stage / '.wonad-stage.json').read_text())
    sources = []
    for name, expected in metadata['files'].items():
        if name == 'WonadSigning.kt' or name.endswith('.kt') and name.startswith((
                'broker-core/src/main/kotlin/', 'os-integration/src/')):
            path = stage / name
            if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError('Staged source differs from its owned marker: ' + name)
            sources.append(path)
    if not sources:
        raise ValueError('No staged broker source')
    module = source / 'out/soong/.intermediates/frameworks/base/libs/WindowManager/Shell/WindowManager-Shell/android_common'
    build = ET.parse(module / 'kotlinc-build.xml')
    paths = []
    for node in build.findall('.//classpath'):
        value = node.attrib['path']
        if not value.startswith('/sources/grapheneos/'):
            raise ValueError('Unexpected compiler classpath prefix: ' + value)
        paths.append(source / value.removeprefix('/sources/grapheneos/'))
    shell = module / 'kotlin/WindowManager-Shell.jar'
    # Real compiled Shell code supplies its internal API; friend paths let
    # the focused adapter retain its original Kotlin module visibility.
    paths += [shell, module / 'javac/WindowManager-Shell.jar']
    if not all(path.is_file() for path in paths):
        raise ValueError('Complete pinned framework/Shell build classpaths required')
    output = args.output.resolve()
    if output.exists() or output.suffix != '.jar' or output.is_relative_to(stage):
        raise ValueError('Use a new output JAR outside the staged sources')
    output.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'JAVA_HOME': str(source / 'prebuilts/jdk/jdk21/linux-x86')}
    command = [str(source / 'external/kotlinc/bin/kotlinc'), '-J-Xmx2048M',
               '-Xjvm-default=all', '-Xconsistent-data-class-copy-visibility',
               '-Xfriend-paths=' + str(shell), '-classpath', os.pathsep.join(map(str, paths)),
               *map(str, sorted(sources)), '-d', str(output)]
    completed = subprocess.run(command, env=env, timeout=180)
    print(json.dumps({'broker_adapter_compile': 'passed' if completed.returncode == 0 else 'not_passed',
                      'scope': 'focused_real_framework_compile_not_os_or_runtime_qualification',
                      'kotlin_sources': len(sources), 'output': str(output)}, indent=2))
    return completed.returncode


if __name__ == '__main__':
    raise SystemExit(main())
