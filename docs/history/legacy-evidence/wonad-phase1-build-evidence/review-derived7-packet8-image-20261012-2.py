"""Independent bounded actual derived7 inspection; no Android guest."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

ROOT = Path('/u/elric/tree/wonad')
OUT = ROOT / 'android/out/phase1-conformance-candidate-custom7-5-7'
NATIVE_OUT = ROOT / 'android/out/phase1-native-candidate-custom7-5-5'
IMAGE = 'sha256:e23259f2cd466b9635d4348c57ac07b0d02750ff89ca0b650b7dc3e45f79b772'
NATIVE = 'sha256:0e425e724cb6f53cb1ef6ae080c39dfdfcf810b5e6fe7c262e419e2b750a01b4'
TAG = 'wonad:phase1-conformance-candidate-custom7-5-7'
MANIFEST_SHA = 'e967bcd1c419935453f9f7d44176eca9a0eead42083ab9c3181bd37c20dc4b51'
NATIVE_MANIFEST_SHA = '72cf4f3e03cd3774c88095ce3bf933f6ba23b043bb9a87de5b1d7f5cbaa66bd7'
BASE_MANIFEST_SHA = '27671c1fd130ddac1e7dfc95b0cd6398bbcdb29e9f9b7d9a9bea6124e0804678'
PACKET_SHA = 'b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee'
PRODUCT = Path('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x')
SOURCES = {
    'conformance_smoke.py': ('android/tools/conformance_smoke.py', 'd193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5'),
    'common.py': ('android/tools/phase1_conformance_common.py', '731d79dbe9818d94a00c10146035109b9b1e0d1fe7ce8b546b575424164e4a94'),
    'driver.py': ('android/tools/phase1_conformance_guest.py', 'b111174b10a735dc7bd9f6256604fe3961974bc064aff04d058b61b45d2ebfd5'),
    'acceptance.py': ('android/tools/phase1_conformance_acceptance.py', 'ede7566d7227a014bd984678d5e5c39a090824edfb0b250f2392728014da99af'),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(raw):
    return json.loads(raw, object_pairs_hook=unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def main():
    observations = []
    docker = ['/usr/bin/docker', '--host', 'unix:///var/run/docker.sock']
    env = os.environ.copy()
    for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
        env.pop(key, None)

    def run(args, timeout=120):
        command = docker + args
        start = time.monotonic_ns()
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, timeout=timeout)
        end = time.monotonic_ns()
        assert len(result.stdout) <= 262144 and len(result.stderr) <= 262144
        observations.append(dict(argv=command, started_monotonic_ns=start, ended_monotonic_ns=end,
            returncode=result.returncode, stdout_bytes=len(result.stdout), stderr_bytes=len(result.stderr),
            stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr),
            stdout=result.stdout.decode('utf-8'), stderr=result.stderr.decode('utf-8')))
        assert result.returncode == 0, observations[-1]
        return result.stdout

    builder_path = ROOT / 'android/container/build-phase1-conformance-candidate.py'
    builder_raw = builder_path.read_bytes()
    assert sha(builder_raw) == 'c2719ce245bd68651401e46f92d09ecf2614629aa3eb07760f4fad24fd2dbebc'
    spec = importlib.util.spec_from_file_location('derived7_independent_builder', builder_path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    manifest_raw = (OUT / 'manifest.json').read_bytes()
    native_raw = (NATIVE_OUT / 'manifest.json').read_bytes()
    base_raw = (OUT / 'product-candidate-manifest.json').read_bytes()
    assert sha(manifest_raw) == MANIFEST_SHA and len(manifest_raw) == 15137
    assert sha(native_raw) == NATIVE_MANIFEST_SHA and len(native_raw) == 62912
    assert sha(base_raw) == BASE_MANIFEST_SHA and len(base_raw) == 49271
    manifest, native_manifest, base = map(decode, (manifest_raw, native_raw, base_raw))
    assert base == native_manifest
    assert (OUT / 'built-image.id').read_text().strip() == IMAGE
    native = decode(run(['image', 'inspect', NATIVE]))
    actual = decode(run(['image', 'inspect', IMAGE]))
    assert len(native) == len(actual) == 1
    native, actual = native[0], actual[0]
    assert native['Id'] == NATIVE and actual['Id'] == IMAGE
    assert run(['image', 'inspect', '--format', '{{.Id}}', TAG]).decode().strip() == IMAGE
    builder.validate_derived_image(native, actual)
    expected_config = dict(native['Config'])
    expected_labels = dict(native['Config']['Labels'])
    expected_labels.update({
        'org.opencontainers.image.title': 'Wonad Phase-1 fresh-guest conformance candidate',
        'org.opencontainers.image.description': 'Unqualified test-only OS-contract image; product Wonad absent; no runtime pass claimed',
    })
    expected_config.update(Entrypoint=['python3', '/opt/wonad/phase1-conformance-entrypoint.py'],
                           Cmd=['verify'], WorkingDir='/state', ArgsEscaped=True, Labels=expected_labels)
    assert actual['Config'] == expected_config
    layers = native['RootFS']['Layers']
    actual_layers = actual['RootFS']['Layers']
    assert len(layers) == 92 and len(actual_layers) == 96
    assert actual_layers[:92] == layers
    assert actual_layers[-1] == builder.CANONICAL_EMPTY_TAR_DIFF_ID
    assert builder.CANONICAL_EMPTY_TAR_DIFF_ID not in actual_layers[92:-1]
    builder.validate_phase1_base_evidence(base, PRODUCT)
    builder.validate_manifest(manifest)
    assert len(manifest['files']) == 59
    assert manifest['base_product_candidate']['image_id'] == NATIVE
    assert manifest['base_product_candidate']['manifest_sha256'] == sha(base_raw)
    assert manifest['packet']['receipt_sha256'] == PACKET_SHA
    assert not manifest['runtime_qualified'] and not manifest['guests_started']
    assert not manifest['production_identity'] and not manifest['product_apk_present']
    assert '/opt/wonad/wonad.apk' not in manifest['files']
    packet_raw = (ROOT / 'android/out/phase1-emulator-client-packet-20261012-8/receipt.json').read_bytes()
    assert sha(packet_raw) == PACKET_SHA
    receipt = decode(packet_raw)
    for role in ('wonad', 'conformance', 'fixture', 'fault'):
        assert manifest['artifacts'][role] == builder.artifact_subset(receipt['artifacts'][role], role)
    source_closure = {}
    assert set(SOURCES) == set(builder.SOURCE_FILES)
    for name, (relative, expected_sha) in SOURCES.items():
        source = ROOT / relative
        current = source.read_bytes()
        staged = (OUT / 'phase1-conformance' / name).read_bytes()
        assert sha(current) == sha(staged) == expected_sha
        assert manifest['files']['/opt/wonad/phase1-conformance/' + name] == expected_sha
        source_closure[name] = dict(path=str(source), sha256=expected_sha, bytes=len(current))
    raw = run(['run', '--rm', '--network', 'none', '--read-only', '--tmpfs',
               '/tmp:rw,nosuid,size=64m', IMAGE, 'verify'])
    banner, separator, document = raw.partition(b'\n')
    assert banner.decode() == 'Verifying fresh-guest Phase-1 conformance candidate…' and separator
    assert decode(document) == manifest
    run(['run', '--rm', '--network', 'none', '--read-only', '--entrypoint', '/bin/sh',
         IMAGE, '-ec', 'test ! -e /opt/wonad/wonad.apk'])
    assert run(['image', 'inspect', '--format', '{{.Id}}', TAG]).decode().strip() == IMAGE
    assert (OUT / 'manifest.json').read_bytes() == manifest_raw
    assert (OUT / 'product-candidate-manifest.json').read_bytes() == base_raw
    print(json.dumps(dict(schema=1, kind='wonad-phase1-derived7-bounded-independent-offline-audit',
        status='passed_offline_metadata_inventory_source_packet_checks_not_runtime_qualified',
        image_id=IMAGE, native_image_id=NATIVE, manifest_sha256=MANIFEST_SHA,
        manifest_bytes=len(manifest_raw), base_manifest_sha256=BASE_MANIFEST_SHA,
        native_manifest_raw_sha256=NATIVE_MANIFEST_SHA, packet_receipt_sha256=PACKET_SHA,
        files=59, native_layer_count=92, derived_layer_count=96, delta=actual_layers[92:],
        full_config_matches_only_Dockerfile_changes_plus_pinned_BuildKit_ArgsEscaped_true=True,
        exact_native_layer_prefix=True, original_product_binding_passed=True,
        native_and_derived_base_manifest_semantically_equal=True,
        offline_verifier_equals_exact_manifest=True,
        offline_verifier_checks_all59_checksums=True, separate_product_APK_absence_passed=True,
        artifact_subsets_equal_exact_packet=True, source_closure=source_closure,
        observations=observations, runtime_qualified=False, vm_started=False,
        initial_audit_assumption_failure=dict(script_sha256='bd941a16af2788ef540010a801b7b46a69ca1c69bac4da9f55ccb5fbf30014ad',
            session=52922, tool_chunk='25ace7', exit_code=1,
            scope='Before verifier container; expected full Config omitted exact title/description LABEL changes from pinned Dockerfile',
            actual_config_delta_chunk='27e651', product_defect_claimed=False),
        claim_limits=['No actual Android boot or contract/runtime qualification',
                      'Final tag checks are not atomic namespace CAS']), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
