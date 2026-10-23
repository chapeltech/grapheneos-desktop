#!/usr/bin/env bash
# The immutable-builder half of Frankel vendor generation.
#
# Source authentication and cache cleanup deliberately do not belong here:
# they use host-pinned tools and are owned by run_frankel_vendor.py on the
# host.  This action may only install the pinned adevtool JavaScript
# dependencies, build every upstream host-tool target, verify that handoff,
# and generate the authenticated Frankel vendor module.
set -euo pipefail

die() { echo "generate-frankel-vendor.sh: $*" >&2; exit 2; }

[[ $# == 0 ]] || die 'this builder action takes no arguments'
[[ $(id -u) == 1000 && $(id -g) == 1000 ]] || die 'run as UID/GID 1000:1000'

source_dir=${WONAD_GRAPHENEOS_RELEASE_SOURCE:-}
device=${WONAD_VENDOR_DEVICE:-}
yarn_bin=${WONAD_YARN_BIN:-}
expected_adevtool_commit=${WONAD_ADEVTOOL_COMMIT:-}

[[ "$source_dir" == /grapheneos ]] || die 'source must be the reviewed /grapheneos bind'
[[ "$PWD" == /grapheneos ]] || die 'working directory must be /grapheneos'
[[ "$device" == frankel ]] || die 'only the reviewed Frankel target is supported'
[[ "$yarn_bin" == /usr/bin/yarnpkg && -x "$yarn_bin" ]] || die 'pinned yarn path differs'
[[ "$ADEVTOOL_IMG_DOWNLOAD_DIR" == /adevtool-images ]] || die 'factory cache bind differs'
[[ "$expected_adevtool_commit" =~ ^[0-9a-f]{40}$ ]] || die 'adevtool commit pin is malformed'
[[ $(node --version) == v24.21.0 ]] || die 'Node.js version differs'
[[ $("$yarn_bin" --version) == 1.22.19 ]] || die 'Yarn version differs'

for path in vendor/adevtool vendor/adevtool/yarn.lock vendor/adevtool/bin/run; do
    [[ -e "$path" && ! -L "$path" ]] || die "missing or symlinked input: $path"
done
[[ ! -e vendor/google_devices/frankel && ! -L vendor/google_devices/frankel ]] ||
    die 'Frankel output must be absent before generation'

mkdir -m 0700 -- /tmp/wonad-vendor-home /tmp/wonad-vendor-yarn-cache
"$yarn_bin" --cwd vendor/adevtool install --frozen-lockfile --non-interactive

# Run the exact upstream build separately. adevtool's internal spawn wrapper
# rejects the observed nonfatal nsjail/ckati diagnostics even after Siso
# succeeds. Do not patch upstream, loosen Docker, hide stderr, or omit targets.
# The documented skip flag below skips ONLY a redundant second build, after
# this fresh full build and all fourteen installed programs have been checked.
/usr/bin/python3 - "$expected_adevtool_commit" <<'WONAD_DEPENDENCY_HANDOFF_PY'
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys

TARGETS = ('aapt2', 'apksigner', 'aprotoc', 'arsclib', 'debugfs', 'dispol',
           'fsck.erofs', 'lpdump', 'lpunpack', 'lz4', 'ota_extractor',
           'simg2img', 'sqlite3', 'toybox')
SCRIPT_SHA = '02183ec2528b0305007e9a2f0d6dacc5312e72d483b18ccd7653cab47e06c785'
PATHS_SHA = '418823cca30a381208e13acd7ea30d5ff37be411f1492ccd05f290ba4c95bd8e'
COMMAND = ['/grapheneos/vendor/adevtool/scripts/run-build.sh',
           'sdk_phone64_x86_64', 'out_adevtool_deps', *TARGETS]
STDOUT_LIMIT = 128 * 1024 * 1024
STDERR_LIMIT = 4096


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def regular_bytes(path, limit):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and path.resolve(strict=True) == path,
            'Not a canonical regular file: ' + str(path))
    require(before.st_size <= limit, 'Capture limit exceeded: ' + str(path))
    def same(left, right):
        return all(getattr(left, field) == getattr(right, field) for field in
                   ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                    'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        require(same(os.fstat(stream.fileno()), before), 'File changed before read')
        payload = stream.read(limit + 1)
        require(len(payload) <= limit and same(os.fstat(stream.fileno()), before)
                and same(path.lstat(), before), 'File changed during read')
    return payload


def reference(path, payload):
    return {'path': str(path), 'bytes': len(payload),
            'sha256': hashlib.sha256(payload).hexdigest()}


def classify_transcripts(exit_code, stdout, stderr):
    require(type(exit_code) is int and exit_code == 0,
            'Dependency compiler did not return exact zero')
    require(len(stdout) <= STDOUT_LIMIT and len(stderr) <= STDERR_LIMIT,
            'Dependency transcript capture limit exceeded')
    lines = stdout.decode('utf-8', errors='strict').splitlines()
    footer = re.compile(r'ninja: (?:\d+h)?(?:\d+m)?\d+(?:\.\d+)?s '
                        r'Build Succeeded: [1-9]\d* steps - \d+(?:\.\d+)?/s')
    footers = [line for line in lines if footer.fullmatch(line)]
    require(1 <= len(footers) <= 16, 'Missing or excessive actual Siso success footers')
    require(not any(line.startswith(('FAILED:', 'ninja: build stopped:')) for line in lines),
            'Failure marker in dependency stdout')
    warnings = []
    counts = {'sandbox_fallback': 0, 'ckati_affinity_einval': 0}
    for line in stderr.decode('utf-8', errors='strict').splitlines():
        if re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d '
                        r'Build sandboxing disabled due to nsjail error\.', line):
            kind = 'sandbox_fallback'
        elif line == 'sched_setaffinity: Invalid argument':
            kind = 'ckati_affinity_einval'
        else:
            raise RuntimeError('Unknown dependency stderr line: ' + repr(line))
        counts[kind] += 1
        warnings.append({'kind': kind, 'raw_line': line})
    require(counts['sandbox_fallback'] <= 1 and counts['ckati_affinity_einval'] <= 2,
            'Observed dependency warning count exceeded reviewed bounds')
    return {'siso_success_footers': footers, 'retained_warnings': warnings}


def capture_build(command, stdout_path, stderr_path):
    # Both byte streams are retained unchanged and forwarded unchanged. A cap
    # failure terminates only this exact child process group and remains failed.
    with open(stdout_path, 'xb') as out, open(stderr_path, 'xb') as err:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ,
                                  (out, sys.stdout.buffer, STDOUT_LIMIT))
                selector.register(child.stderr, selectors.EVENT_READ,
                                  (err, sys.stderr.buffer, STDERR_LIMIT))
                while selector.get_map():
                    for key, _ in selector.select():
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        sink, forwarded, limit = key.data
                        sink.write(chunk)
                        sink.flush()
                        forwarded.write(chunk)
                        forwarded.flush()
                        require(sink.tell() <= limit, 'Dependency transcript capture limit exceeded')
            return child.wait()
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            child.stdout.close()
            child.stderr.close()
            for stream in (out, err):
                stream.flush()
                os.fsync(stream.fileno())


def retain_program(path, destination):
    payload = regular_bytes(path, 128 * 1024 * 1024)
    require(len(payload) > 0, 'Installed program is empty')
    require(Path(path).stat().st_mode & 0o111, 'Installed program is not executable')
    with open(destination, 'xb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return {'installed_path': str(path), 'retained': reference(destination, payload)}


def main():
    require(len(sys.argv) == 2 and re.fullmatch(r'[0-9a-f]{40}', sys.argv[1]),
            'Malformed dependency handoff invocation')
    require(Path.cwd() == Path('/grapheneos'), 'Wrong dependency source bind')
    require(not os.path.lexists('out_adevtool_deps'), 'Dependency OUT must be fresh')
    for path, digest in ((Path(COMMAND[0]), SCRIPT_SHA),
                         (Path('vendor/adevtool/src/config/paths.ts'), PATHS_SHA)):
        require(hashlib.sha256(regular_bytes(path.absolute(), 1024 * 1024)).hexdigest()
                == digest, 'Pinned upstream dependency input differs: ' + str(path))
    evidence = Path('/adevtool-images/wonad-dependency-build')
    evidence.mkdir(mode=0o700)
    (evidence / 'programs').mkdir(mode=0o700)
    out, err = evidence / 'stdout.raw', evidence / 'stderr.raw'
    receipt = {'schema': 1, 'kind': 'phase1_adevtool_dependency_handoff_v1',
               'status': 'failed', 'adevtool_commit': sys.argv[1],
               'command': COMMAND, 'targets': list(TARGETS),
               'upstream_script_sha256': SCRIPT_SHA, 'upstream_paths_sha256': PATHS_SHA,
               'skip_flag_scope': 'redundant second build only after fresh full build',
               'compiler_exit_code': None, 'programs': {}}
    try:
        print('Building all fourteen upstream adevtool host targets; raw logs retained.', flush=True)
        receipt['compiler_exit_code'] = capture_build(COMMAND, out, err)
        stdout, stderr = regular_bytes(out, STDOUT_LIMIT), regular_bytes(err, STDERR_LIMIT)
        receipt['stdout'] = reference(out, stdout)
        receipt['stderr'] = reference(err, stderr)
        receipt['classification'] = classify_transcripts(receipt['compiler_exit_code'], stdout, stderr)
        for name in TARGETS:
            receipt['programs'][name] = retain_program(
                Path('/grapheneos/out_adevtool_deps/host/linux-x86/bin') / name,
                evidence / 'programs' / name)
        receipt['status'] = 'built_and_verified'
        print('PASS: fresh full adevtool dependency build and fourteen retained program hashes.', flush=True)
    except BaseException as error:
        receipt['error'] = {'class': type(error).__name__, 'message': str(error)}
        raise
    finally:
        with open(evidence / 'receipt.json', 'x') as stream:
            json.dump(receipt, stream, sort_keys=True, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())


if __name__ == '__main__':
    main()
WONAD_DEPENDENCY_HANDOFF_PY

ADEVTOOL_SKIP_DEP_BUILD=1 vendor/adevtool/bin/run generate-all -d "$device"

vendor=vendor/google_devices/frankel
[[ -d "$vendor" && ! -L "$vendor" ]] || die 'adevtool did not create the Frankel vendor directory'
for path in Android.mk AndroidProducts.mk BoardConfig.mk README.md frankel.mk \
            adevtool-version-check.mk; do
    [[ -f "$vendor/$path" && ! -L "$vendor/$path" ]] ||
        die "adevtool output is missing an ordinary $path"
done
for path in proprietary firmware; do
    [[ -d "$vendor/$path" && ! -L "$vendor/$path" ]] ||
        die "adevtool output is missing an ordinary $path directory"
done

expected_version=$(printf '%s\n%s\n%s' \
    "ifneq (\$(shell git -C vendor/adevtool rev-parse HEAD),$expected_adevtool_commit)" \
    '  $(error frankel vendor module is outdated. Run `adevtool generate-all -d frankel` to update it)' \
    'endif')
cmp -s -- "$vendor/adevtool-version-check.mk" <(printf '%s' "$expected_version") ||
    die 'generated adevtool version guard differs from the pinned revision'

echo 'PASS: immutable builder generated the pinned Frankel vendor module'
