#!/usr/bin/env python3
"""Prepared two-lane launch admission for the future packet8 candidate.

API and Recents retain separate fresh boots, output trees and independent
auditors.  This generation is intentionally non-executable until packet8,
wrong-signer bundle8, native5/derived7 and their selection are all published
and independently reviewed.  Check-only also fails while any pin is pending;
it never substitutes a current/latest artifact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


ROOT = Path('/u/elric/tree/wonad')
EVIDENCE = Path('/u/elric/tree/wonad-phase1-build-evidence')
AUTHORITY = ROOT / 'android/out/phase1-evidence-custom7-5'
PACKET = ROOT / 'android/out/phase1-emulator-client-packet-20261012-8'
PACKET_SHA = 'PENDING_ACTUAL_PACKET8_RECEIPT_SHA256'
WRONG = ROOT / 'android/out/phase1-wrong-signer-bundle-20261012-8/signing-receipt.json'
WRONG_SHA = 'PENDING_ACTUAL_WRONG_SIGNER_BUNDLE8_RECEIPT_SHA256'
PYTHON = Path('/srv/wonad-os37-pending-permission-3/wonad-styx-live.0DimSmO9/x11-test-venv/bin/python3')
SELECTION = EVIDENCE / 'phase1-custom7-api-recents-packet8-selection-20261012-7.json'
SELECTION_SHA = 'PENDING_ACTUAL_NATIVE5_DERIVED7_SELECTION_SHA256'
PRODUCT_ORIGIN = Path('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x')
DEBUG_ID = 'e5e8d4c4d2b1373416027fa86d88a5d9e6d6d3e3592c0b9cabcf80a6b59ffc4d'
DEBUG_PROOF = EVIDENCE / 'phase1-custom7-preserved-debug-sleep-adb-proof-20261011-1.json'
DEBUG_PROOF_SHA = '49ee022282157cbe77b215660a8afcf98c75184872b1cb93b1e902f9c85d24f8'
OUTPUTS = {
    'api': AUTHORITY / 'runtime-api-packet8-20261012-7',
    'recents': AUTHORITY / 'runtime-recents-packet8-20261012-7',
}
LABEL = 'org.wonad.phase1-fresh-conformance'
PENDING = {
    'packet': 'PENDING_ACTUAL_PACKET8_RECEIPT_SHA256',
    'wrong': 'PENDING_ACTUAL_WRONG_SIGNER_BUNDLE8_RECEIPT_SHA256',
    'selection': 'PENDING_ACTUAL_NATIVE5_DERIVED7_SELECTION_SHA256',
}
SOURCE_SHA = {
    'android/tools/phase1_conformance_guest.py': 'b111174b10a735dc7bd9f6256604fe3961974bc064aff04d058b61b45d2ebfd5',
    'android/tools/phase1_conformance_acceptance.py': 'ede7566d7227a014bd984678d5e5c39a090824edfb0b250f2392728014da99af',
    'android/tools/run_phase1_conformance_recents_guest.py': '51d7e54f63fa5de622553a1beaff1a61b2641218c32626a679c9d6d176733c7b',
    'android/tools/phase1_conformance_recents.py': 'd132b503da89f8b1ed538ba41210d2eca4fce6ade768db75aaaba4d39cd1e682',
    'android/tools/phase1_conformance_recents_acceptance.py': '62984b8df64dbb2fb22f39fbffc1c4bdc4719a2463456f9a8c4c34696826ac92',
    'android/tools/phase1_conformance_recents_guest_acceptance.py': 'c43b6275c1d2c9ad155db2d7d4a65f9cdf03f0699852e476de12a5f187328447',
    'android/tools/phase1_conformance_common.py': '731d79dbe9818d94a00c10146035109b9b1e0d1fe7ce8b546b575424164e4a94',
    'android/tools/conformance_smoke.py': 'd193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5',
    'android/tools/phase1_emulator_client_packet.py': 'defd7f981ee6ff4317c57730bfeeaa0ab84f39aa1585b446ed4db92f250a60d2',
    'android/tools/run_native_matrix.py': 'f29b136a2ea62c02c7c722f2746a4ce92b8ea666e87ba1c0656d028d7d68be8e',
    'android/tools/docker_locality_proof.py': '09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780',
    'android/container/build-phase1-conformance-candidate.py': 'c2719ce245bd68651401e46f92d09ecf2614629aa3eb07760f4fad24fd2dbebc',
    'android/container/build-native-candidate.py': '70ccf59510dfcf11217e640c180016c7fb5d2d22b1da9adb38bd59c100cd226d',
    'android/container/build.py': 'deae860dd19274b6137ce0c856b1e22179ea116494ab895a84ab7f99927779b1',
    'android/demo/session.py': 'f18f9515c13af0677c2911a090d365e1da0ef623c881f881a834cc17784cfccb',
    'android/demo/emulator_identity.py': 'aa511be85d93a288664b10ccf79c6b5d068d871fc6bddacd963ff39c9359d2ba',
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    require(path.is_file() and not path.is_symlink() and
            path.resolve(strict=True) == path, 'Missing/aliased pinned file: ' + str(path))
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def unique(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'Duplicate JSON field: ' + key)
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_bytes(), object_pairs_hook=unique)


def actual_identity_ready():
    values = {'packet': PACKET_SHA, 'wrong': WRONG_SHA, 'selection': SELECTION_SHA}
    for role, value in values.items():
        require(value != PENDING[role] and isinstance(value, str) and
                re.fullmatch('[0-9a-f]{64}', value),
                'NOT READY: actual packet8/wrong8/native5/derived7 selection pins are pending')


def guest_directory(lane):
    # Recents orchestration nests its fresh common guest at output/guest;
    # the direct API producer owns its top-level output. Use the same mapping
    # for both the bind-source check and the repository inspector argument.
    return OUTPUTS[lane] / 'guest' if lane == 'recents' else OUTPUTS[lane]


def docker_output(arguments):
    from docker_locality_proof import DOCKER, ENDPOINT, command_environment
    return subprocess.check_output([str(DOCKER), '--host', ENDPOINT, *arguments],
            env=command_environment(dict(os.environ)), text=True, timeout=30)


def local_inputs():
    require(os.getuid() == os.getgid() == 1000, 'Use the owned UID/GID1000 host lane')
    require(AUTHORITY.resolve(strict=True) == AUTHORITY and AUTHORITY.is_dir(), 'Authority root missing/aliased')
    for name, expected in SOURCE_SHA.items():
        require(digest(ROOT / name) == expected, 'Reviewed runtime source changed: ' + name)
    require(digest(PACKET / 'receipt.json') == PACKET_SHA, 'Packet8 receipt changed')
    require(digest(WRONG) == WRONG_SHA, 'Packet8 wrong-signer receipt changed')
    require(digest(Path('/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7/external/wonad/.wonad-stage.json')) ==
            '5fb1f000c37ab702bbd2722d4dde6d1936d792533d2e76798e8ce59e271c0d5d', 'Current custom7 stage marker changed')
    sys.path.insert(0, str(ROOT / 'android/tools'))
    import phase1_emulator_client_packet as packet_tool
    packet_tool.validate_receipt(PACKET, load(PACKET / 'receipt.json'), PACKET_SHA, live_tools=False)
    require(stat.S_ISCHR(Path('/dev/kvm').stat().st_mode) and
            os.access('/dev/kvm', os.R_OK | os.W_OK), 'Host KVM permission unavailable')
    import PIL
    require(PIL.__version__ == '12.3.0', 'Use the selected Pillow12.3.0 interpreter')


def commands(selection, lane, audit=False):
    producer = {'api': 'phase1_conformance_guest.py',
                'recents': 'run_phase1_conformance_recents_guest.py'}[lane]
    auditor = {'api': 'phase1_conformance_acceptance.py',
               'recents': 'phase1_conformance_recents_guest_acceptance.py'}[lane]
    common = ['--product', selection['product'], '--packet', str(PACKET),
              '--expected-receipt-sha256', PACKET_SHA]
    if audit:
        return [str(PYTHON), '-B', str(ROOT / 'android/tools' / auditor),
                '--report', str(OUTPUTS[lane] / 'report.json'), *common]
    return [str(PYTHON), '-B', str(ROOT / 'android/tools' / producer),
            '--image', selection['derived_image_id'], *common,
            '--output', str(OUTPUTS[lane])]


def selected():
    require(SELECTION_SHA != PENDING['selection'] and isinstance(SELECTION_SHA, str) and
            re.fullmatch('[0-9a-f]{64}', SELECTION_SHA),
            'NOT READY: actual native5/derived7 image selection is not frozen yet')
    require(digest(SELECTION) == SELECTION_SHA, 'Frozen image selection changed')
    value = load(SELECTION)
    require(set(value) == {'schema', 'scope', 'native_image_id', 'derived_image_id',
            'native_manifest', 'native_manifest_sha256', 'derived_manifest',
            'derived_manifest_sha256', 'product', 'packet_receipt_sha256',
            'baseline_receipt_sha256', 'custom_receipt_sha256', 'comparison_sha256'} and
            type(value['schema']) is int and value['schema'] == 1 and value['scope'] ==
            'custom7-packet8-two-separate-fresh-guests-not-runtime-qualified' and
            value['packet_receipt_sha256'] == PACKET_SHA, 'Wrong frozen selection grammar')
    for role in ('native', 'derived'):
        require(re.fullmatch('sha256:[0-9a-f]{64}', value[role + '_image_id']), 'Mutable image selection')
        path = Path(value[role + '_manifest'])
        require(path.is_relative_to(AUTHORITY), 'Manifest outside custom7 authority')
        require(digest(path) == value[role + '_manifest_sha256'], 'Selected manifest changed: ' + role)
    product = Path(value['product'])
    require(product == PRODUCT_ORIGIN and product.resolve(strict=True) == product and product.is_dir(),
            'Product bundle is not the original authenticated custom7 OUT product')
    from phase1_conformance_common import validate_manifest, canonical_sha256
    derived, native = load(Path(value['derived_manifest'])), load(Path(value['native_manifest']))
    validate_manifest(derived)
    require(derived['packet']['receipt_sha256'] == PACKET_SHA and
            derived['base_product_candidate']['image_id'] == value['native_image_id'] and
            derived['base_product_candidate']['manifest_sha256'] == canonical_sha256(native),
            'Derived/native/packet identities differ')
    evidence = native['phase1_build_evidence']
    for role in ('baseline_receipt', 'custom_receipt', 'comparison'):
        require(evidence[role]['expected_sha256'] == value[role + '_sha256'],
                'Wrong strict build-evidence identity: ' + role)
    require(evidence['client_packet']['expected_sha256'] == PACKET_SHA, 'Historical packet in native manifest')
    from phase1_conformance_guest import candidate_builder
    candidate_builder.validate_phase1_base_evidence(native, product)
    actual = {}
    for role in ('native', 'derived'):
        rows = json.loads(docker_output(['image', 'inspect',
            value[role + '_image_id']]), object_pairs_hook=unique)
        require(len(rows) == 1 and rows[0]['Id'] == value[role + '_image_id'],
                'Actual immutable image is unavailable or substituted: ' + role)
        actual[role] = rows[0]
    candidate_builder.validate_derived_image(actual['native'], actual['derived'])
    return value


def preserved_debug_check(info):
    # Root approved only this literal preexisting sleep/ADB container. It is
    # never a guest, never mutated, and is NOT returned as an allowed QEMU ID.
    require(digest(DEBUG_PROOF) == DEBUG_PROOF_SHA, 'Preserved debug observation changed')
    proof = load(DEBUG_PROOF)
    expected = json.loads(proof['inspect_result']['output'], object_pairs_hook=unique)[0]
    require(proof['scope'] == 'read-only-preserved-debug-sleep-adb-not-guest' and
            expected['Id'] == DEBUG_ID and info['Id'] == DEBUG_ID and
            all(info[key] == expected[key] for key in ('Image', 'Name', 'Path', 'Args', 'Config', 'HostConfig')) and
            sorted(info['Mounts'], key=lambda row: row['Destination']) ==
            sorted(expected['Mounts'], key=lambda row: row['Destination']) and
            info['State']['Running'] is True and info['State']['Paused'] is False and
            info['State']['Restarting'] is False and info['State']['Dead'] is False and
            info['State']['Pid'] == expected['State']['Pid'] and
            info['State']['StartedAt'] == expected['State']['StartedAt'],
            'Preserved debug identity/profile changed; no generic KVM exemption')
    command = ['docker', 'top', DEBUG_ID, '-eo', 'pid,ppid,comm,args']
    require(proof['top_command'] == command, 'Wrong retained debug top command')
    current = docker_output(['top', DEBUG_ID, '-eo', 'pid,ppid,comm,args'])
    require(len(current.encode()) <= 65536, 'Debug process listing exceeds bounded observation')
    def rows(raw):
        lines = raw.splitlines()
        require(lines and lines[0].split() == ['PID', 'PPID', 'COMMAND', 'COMMAND'],
                'Unexpected debug process header')
        values = [line.split(None, 3) for line in lines[1:] if line.strip()]
        require(all(len(row) == 4 and row[0].isdecimal() and row[1].isdecimal()
                    for row in values), 'Unexpected debug process grammar')
        return sorted(values)
    observed = rows(proof['top_result']['output'])
    require(len(observed) == 2 and observed == sorted([
            ['2362784', '2362760', 'sleep', 'sleep infinity'],
            ['2363851', '2362784', 'adb', 'adb -L tcp:5037 fork-server server --reply-fd 7']]) and
            rows(current) == observed,
            'Preserved debug must contain only the exact observed sleep infinity and ADB fork-server')


def running_guest_check(selection, lane):
    # This pair may overlap only its exact other private guest. Other KVM
    # containers, native/backend/GUI or OS build runners are excluded.
    raw = docker_output(['ps', '-q', '--no-trunc'])
    peer = 'recents' if lane == 'api' else 'api'
    guests = []
    for identifier in raw.splitlines():
        require(re.fullmatch('[0-9a-f]{64}', identifier), 'Unexpected running container ID')
        infos = json.loads(docker_output(['container', 'inspect', identifier]),
                         object_pairs_hook=unique)
        require(len(infos) == 1 and infos[0]['Id'] == identifier, 'Running container inspect identity differs')
        info = infos[0]
        if identifier == DEBUG_ID:
            preserved_debug_check(info)
            continue
        if not any(device.get('PathOnHost') == '/dev/kvm' for device in info['HostConfig'].get('Devices') or []):
            continue
        nonce = info['Config'].get('Labels', {}).get(LABEL, '')
        mounts = info['Mounts']
        require(info['Id'] == identifier and info['Image'] == selection['derived_image_id'] and
                re.fullmatch('[0-9a-f]{32}', nonce) and
                info['Name'] == '/wonad-phase1-conformance-' + nonce[:12] and
                info['Config']['User'] == '1000:1000' and
                info['HostConfig']['NetworkMode'] == 'none' and not info['HostConfig'].get('PortBindings') and
                len(mounts) == 1 and mounts[0]['Source'] == str(guest_directory(peer) / 'emulator-state') and
                mounts[0]['Destination'] == '/state' and mounts[0]['RW'] is True,
                'Another KVM/native/GUI guest is live; preserve it and do not overlap')
        from phase1_conformance_acceptance import inspected_container
        require(inspected_container({'output': json.dumps([info])},
            {'container': identifier, 'image_id': selection['derived_image_id'],
             'container_run': nonce}, guest_directory(peer), '1000:1000',
            str(Path('/dev/kvm').stat().st_gid)), 'Exact owned peer is not running')
        guests.append(identifier)
    require(len(guests) <= 1, 'Only two API/Recents guests may overlap')
    return guests


def live_process_check(allowed_guests, lane, selection):
    peer = 'recents' if lane == 'api' else 'api'
    peer_script = {'api': 'phase1_conformance_guest.py',
                   'recents': 'run_phase1_conformance_recents_guest.py'}[peer]
    blocked = []
    # Bounded /proc command-line observation, not a memory or filesystem walk.
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal() or int(item.name) == os.getpid():
            continue
        try:
            with (item / 'cmdline').open('rb') as stream:
                raw = stream.read(65537)
            require(len(raw) <= 65536,
                    'Process command line exceeds bounded observation: PID ' + item.name)
            if not raw:
                continue
            argv = [arg.decode(errors='replace') for arg in raw.rstrip(b'\0').split(b'\0')]
            names = {Path(arg).name for arg in argv}
            executable = Path(argv[0]).name
            qemu = executable.startswith('qemu-system') or executable in {'emulator', 'qemu-kvm'}
            runner = any(name in {'run_native_matrix.py', 'run_phase1_runtime_qualification.py',
                'run_phase1_upstream_tests.py', 'run_x86_emulator_build.py',
                'run_frankel_build.py', 'phase1_conformance_guest.py',
                'run_phase1_conformance_recents_guest.py'} or
                (name.startswith('native_') and name.endswith('_smoke.py')) or
                (name.startswith('continue-phase1-x86-custom-7-') and name.endswith('.sh'))
                for name in names)
            compiler = executable in {'ninja', 'siso', 'soong_ui', 'soong_ui.bash'}
            if not (qemu or runner or compiler):
                continue
            if qemu and any(identifier in (item / 'cgroup').read_text()
                            for identifier in allowed_guests):
                continue
            if runner and peer_script in names and argv == commands(selection, peer):
                continue
            blocked.append({'pid': int(item.name), 'executable': executable,
                            'matching_arguments': sorted(names & {
                                'run_native_matrix.py', 'run_phase1_runtime_qualification.py',
                                'run_phase1_upstream_tests.py', 'run_x86_emulator_build.py',
                                'run_frankel_build.py', 'phase1_conformance_guest.py',
                                'run_phase1_conformance_recents_guest.py'})})
        except (FileNotFoundError, ProcessLookupError):
            continue
    require(not blocked, 'Preserve live build/native/GUI/foreign guest lane: ' + json.dumps(blocked))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    parser.add_argument('--lane', choices=('api', 'recents'), default='api')
    parser.add_argument('--execute-after-root-authorization', action='store_true')
    args = parser.parse_args(argv)
    require(args.check_only != args.execute_after_root_authorization,
            'Choose check-only OR explicit root-authorized execution')
    actual_identity_ready()
    local_inputs()
    from docker_locality_proof import command_environment, trusted_local_docker
    environment = command_environment(dict(os.environ))
    _cli, _socket, _context, daemon = trusted_local_docker(environment)
    from run_native_matrix import resources
    budget = resources(2)  # Reserve the full pair even if invoked separately.
    selection = selected()
    require(not OUTPUTS[args.lane].exists() and not OUTPUTS[args.lane].is_symlink(),
            'Preserve preexisting lane output; use a fresh successor driver')
    peers = running_guest_check(selection, args.lane)
    live_process_check(peers, args.lane, selection)
    producer = commands(selection, args.lane)
    print(json.dumps({'status': 'admitted_nonreserving_not_guest_verified',
          'lane': args.lane, 'budget': budget, 'owned_peer_guest_ids': peers,
          'local_docker_daemon_id': daemon['id'],
          'producer': producer, 'independent_auditor': commands(selection, args.lane, audit=True),
          'actual_offline_image_and_product_verification': 'required_by_repository_producer_before_guest'},
          sort_keys=True), flush=True)
    if args.check_only:
        return 0
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    os.chdir(ROOT)
    os.execve(PYTHON, producer, environment)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2)

