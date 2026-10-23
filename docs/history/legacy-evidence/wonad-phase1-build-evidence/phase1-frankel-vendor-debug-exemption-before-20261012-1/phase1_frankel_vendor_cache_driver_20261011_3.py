#!/usr/bin/env python3
"""Create-only successor for authenticated-cache Frankel vendor preparation.

This entry point captures and authenticates the unexecuted v2 policy core as
one regular file, executes those captured bytes (never a second pathname
read), substitutes only this successor's fresh paths, and strengthens the
cache receipt read and second admission ordering.  Default operation is a
read-only check.  Only explicit ``--run`` may create the FICLONE workspace;
there is no copy/download fallback for the cached factory archive.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import types

sys.dont_write_bytecode = True

EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
CORE = EVIDENCE / 'phase1_frankel_vendor_cache_driver_20261011_2.py'
CORE_SHA256 = '9a477928470e22d4445234775c139b5782d113376908f3f135546fed5bdefbf5'
DRIVER = EVIDENCE / 'prepare-phase1-frankel-vendor-cache-20261011-3.sh'
HELPER = EVIDENCE / 'phase1_frankel_vendor_cache_driver_20261011_3.py'
TEST = EVIDENCE / 'test_phase1_frankel_vendor_cache_driver_20261011_3.py'
WORK = EVIDENCE / 'phase1-frankel-vendor-cache-work-20261011-2'
LOG = EVIDENCE / 'phase1-frankel-baseline-vendor-cache-20261011-3.log'
PREFLIGHT = EVIDENCE / 'phase1-frankel-baseline-vendor-cache-20261011-3.preflight.json'
NAME = 'wonad-phase1-frankel-vendor-cache-2026100600-003'
PROOF = EVIDENCE / 'phase1-frankel-vendor-cache-create-only-20261011-5'
PROOF_WORK = PROOF / 'empty-image-cache'
PROOF_NAME = 'wonad-phase1-frankel-vendor-cache-create-only-20261011-5'
MAX_CORE_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024


def _require(value, message):
    if not value:
        raise ValueError(message)


def _same_stat(left, right):
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid',
              'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    return all(getattr(left, key) == getattr(right, key) for key in fields)


def capture_regular(path, maximum):
    """Return bytes+identity from one no-follow fd; pathname swaps fail closed."""
    path = Path(path)
    before = path.lstat()
    _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             path.resolve(strict=True) == path, f'Not one canonical regular file: {path}')
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _require(_same_stat(before, opened), f'File changed before capture: {path}')
        chunks = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        _require(total <= maximum, f'Captured file exceeds {maximum} bytes: {path}')
        after = os.fstat(descriptor)
        _require(_same_stat(opened, after), f'File changed during capture: {path}')
    finally:
        os.close(descriptor)
    _require(_same_stat(before, path.lstat()), f'File pathname changed during capture: {path}')
    payload = b''.join(chunks)
    return payload, {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}


_core_bytes, _core_ref = capture_regular(CORE, MAX_CORE_BYTES)
_require(_core_ref['sha256'] == CORE_SHA256, 'Authenticated vendor-cache policy core differs')
_core = types.ModuleType('phase1_frankel_vendor_cache_policy_core_20261011_2')
_core.__file__ = str(CORE)
exec(compile(_core_bytes, str(CORE), 'exec'), _core.__dict__)

# The captured core is path-parametric at runtime.  Point every output and
# self-binding at this genuinely fresh successor namespace before any check.
for _key, _value in {
    'DRIVER': DRIVER, 'HELPER': HELPER, 'TEST': TEST, 'WORK': WORK,
    'LOG': LOG, 'PREFLIGHT': PREFLIGHT, 'NAME': NAME,
    'PROOF': PROOF, 'PROOF_WORK': PROOF_WORK, 'PROOF_NAME': PROOF_NAME,
}.items():
    setattr(_core, _key, _value)


def cache_snapshot():
    """Authenticate and parse the cache receipt from the same captured bytes."""
    cache = _core.directory(_core.CACHE, expected={
        'device': _core.CACHE_DEVICE, 'inode': _core.CACHE_INODE,
        'mode': 0o700, 'uid': 1000, 'gid': 1000})
    _core.require(sorted(item.name for item in _core.CACHE.iterdir()) == [
        'download-response-headers.txt', _core.ARCHIVE_NAME,
        'preflight-response-headers.txt', 'preflight.json', 'receipt.json'],
        'Factory cache on-disk inventory differs')
    payload, receipt_ref = capture_regular(_core.CACHE_RECEIPT, MAX_RECEIPT_BYTES)
    _core.require(receipt_ref == {
        'sha256': _core.CACHE_RECEIPT_SHA256, 'bytes': 4682},
        'Factory cache receipt identity differs')
    _core.validate_cache_receipt(_core.unique_json(payload, 'factory cache receipt'))
    archive = _core.archive_identity()
    return {'directory': cache, 'receipt': receipt_ref, 'archive': archive,
            'archive_sha256_from_authenticated_receipt': _core.ARCHIVE_SHA256,
            'archive_bytes_not_rehashed_by_host_admission': True}


_core.cache_snapshot = cache_snapshot
_original_validate_cache_receipt = _core.validate_cache_receipt


def validate_cache_receipt(value):
    _original_validate_cache_receipt(value)
    _core.require(value['source_authority']['url_derivation'] ==
                  'pristine adevtool DEFAULT_BASE_DOWNLOAD_URL plus the filename in the exact indexed Frankel factory row',
                  'Factory cache URL derivation differs')
    _core.require(set(value['negative_claims']) == {
        'archive_extracted', 'archive_copied_into_source_tree', 'vendor_preparation_run',
        'source_staged_or_modified', 'container_started', 'compiler_or_build_started',
        'release_keys_generated_or_used', 'image_signed_or_published', 'ota_published',
        'guest_started', 'phone_or_hardware_qualified'},
        'Factory cache negative-claim schema differs')
    transfer = value['transfer']
    _core.require(isinstance(transfer, dict) and transfer.get('exit_code') == 0 and
                  transfer.get('http_code') == 200 and
                  transfer.get('effective_url') == value['archive']['url'] and
                  transfer.get('size_download') == _core.ARCHIVE_BYTES,
                  'Factory cache transfer result differs')
    disk = value['disk']
    _core.require(isinstance(disk, dict) and disk.get('reserve_preserved') is True and
                  isinstance(disk.get('post_transfer_free_bytes'), int) and
                  disk.get('post_transfer_free_bytes', 0) >= disk.get('fixed_reserve_bytes', 1),
                  'Factory cache disk-reserve evidence differs')
    return True


_core.validate_cache_receipt = validate_cache_receipt

_original_process_kind = _core.process_kind


def process_kind(arguments):
    result = _original_process_kind(arguments)
    if result is not None:
        return result
    names = [Path(item).name for item in arguments]
    for name in names:
        if name.startswith('freeze-phase1-native-matrix-') and name.endswith('.sh'):
            return 'native/GUI matrix evidence freeze'
        if 'wrong-signer-bundle' in name and name.endswith(('.py', '.sh')):
            return 'APK wrong-signer bundle build'
    return None


_core.process_kind = process_kind
_original_container_kind = _core.container_kind


def container_kind(info):
    result = _original_container_kind(info)
    if result is not None:
        return result
    if info.get('State', {}).get('Running') is True and isinstance(info.get('Name'), str) and \
            info['Name'].startswith('/wonad-current-cross-'):
        return 'running APK successor cross-build container'
    return None


_core.container_kind = container_kind
_original_base_checks = _core.base_checks


def base_checks(work=None):
    result, environment = _original_base_checks(work)
    current, observed = capture_regular(CORE, MAX_CORE_BYTES)
    _core.require(observed == _core_ref and current == _core_bytes,
                  'Captured vendor-cache policy core changed')
    result['inputs'][str(CORE)] = observed
    result['captured_policy_core'] = {
        'path': str(CORE), **observed, 'executed_from_captured_bytes': True}
    return result, environment


_core.base_checks = base_checks


def preparation(check_only):
    """Require two complete admissions; clone exists only between them."""
    before, environment = base_checks()
    for path in (_core.LOG, _core.PREFLIGHT, _core.WORK):
        _core.fresh(path)
    _core.missing_container(_core.NAME, environment)
    first_resources = _core.resources(environment)
    if check_only:
        print('Read-only admission passed; no reflink/work directory/container was created')
        print(_core.json.dumps(first_resources, sort_keys=True))
        return

    clone = _core.prepare_reflink_workspace(_core.WORK, _core.ARCHIVE)

    # Resource/lane inspection precedes the final full file/cache/Docker
    # identity pass, keeping that pass immediately adjacent to name recheck,
    # preflight publication, and Docker invocation.
    second_resources = _core.resources(environment)
    after, second_environment = base_checks(_core.WORK)
    _core.require(environment == second_environment,
                  'Docker command environment changed between admission gates')
    _core.same_preparation_inputs(before, after)
    _core.require(after['work'] == clone, 'Reflink workspace changed before second admission')
    _core.missing_container(_core.NAME, environment)
    nonce = _core.secrets.token_hex(32)
    argv = _core.command('run', _core.NAME, nonce, _core.WORK)
    _core.write_new(_core.PREFLIGHT, {
        'schema': 1, 'kind': 'phase1_frankel_vendor_cache_literal_preflight_v2',
        'argv': argv, 'inputs': before, 'reflink_workspace': clone,
        'first_admission': first_resources, 'second_admission': second_resources,
        'two_complete_admissions_before_docker': True,
        'no_copy_or_download_fallback_for_factory_archive': True,
        'not_source_freeze_or_vendor_result': True, 'time_unix': int(_core.time.time())})
    result = _core.run_vendor(argv, environment)
    print(f'Vendor workflow exited {result.returncode}; retained '
          f'{_core.NAME}, {_core.WORK}, {_core.LOG}, {_core.PREFLIGHT}')
    print('No source freeze, baseline ARM build, signing or runtime qualification is claimed')
    if result.returncode:
        raise SystemExit(result.returncode)


_core.preparation = preparation

# Export the reviewed pure helpers/constants for the dedicated host tests.
for _name in (
    'require', 'canonical', 'ref', 'directory', 'fresh', 'unique_json',
    'validate_cache_receipt', 'archive_identity', 'git_head', 'run', 'checked',
    'inspect', 'missing_container', 'cpu_set', 'ancestors', 'process_kind',
    'read_process', 'live_lanes', 'container_kind', 'running_container_lanes',
    'resources', 'work_snapshot', 'prepare_reflink_workspace',
    'same_preparation_inputs', 'command', 'expected_binds', 'exact_binds',
    'validate_created', 'owned_never_started', 'write_new', 'write_raw_new',
    'create_only', 'run_vendor', 'PROCESS_ENV', 'PAYLOAD', 'INNER', 'DOCKER',
    'IMAGE', 'MEMORY', 'MIN_SOURCE_FREE', 'TMPFS', 'MAX_CMDLINE', 'FICLONE',
    'CACHE', 'CACHE_RECEIPT', 'ARCHIVE', 'ARCHIVE_NAME', 'ARCHIVE_SHA256',
    'ARCHIVE_BYTES', 'CACHE_RECEIPT_SHA256', 'SOURCE', 'WONAD',
):
    globals()[_name] = getattr(_core, _name)


def main():
    return _core.main()


if __name__ == '__main__':
    raise SystemExit(main())
