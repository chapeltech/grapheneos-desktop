"""Independent actual native5 image audit; no Android guest execution."""
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('/u/elric/tree/wonad')
OUT = ROOT / 'android/out/phase1-native-candidate-custom7-5-5'
IMAGE = 'sha256:0e425e724cb6f53cb1ef6ae080c39dfdfcf810b5e6fe7c262e419e2b750a01b4'
MANIFEST_SHA = '72cf4f3e03cd3774c88095ce3bf933f6ba23b043bb9a87de5b1d7f5cbaa66bd7'
PACKET_SHA = 'b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee'
SOURCES_SHA = 'b6432d0d4bfd1a8922c682657b652fa8b7d8b3d11c4524294a198d3dd85ea4db'


def main():
    source = ROOT / 'android/container/build-native-candidate.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == '70ccf59510dfcf11217e640c180016c7fb5d2d22b1da9adb38bd59c100cd226d'
    assert (OUT / 'built-image.id').read_text().strip() == IMAGE
    spec = importlib.util.spec_from_file_location('root_native5_builder', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual = module.inspect_image(IMAGE)
    tagged = module.inspect_image('wonad:native-v3-candidate-phase1-custom7-5-5')
    assert actual['Id'] == tagged['Id'] == IMAGE
    module.validate_phase1_candidate_image(actual)
    manifest = module.verified_base_manifest(IMAGE)
    raw = (OUT / 'manifest.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_SHA
    assert manifest == json.loads(raw)
    assert len(manifest['files']) == 43
    base = module.inspect_image(module.PHASE1_BASE_IMAGE)
    assert actual['RootFS']['Layers'][:len(base['RootFS']['Layers'])] == base['RootFS']['Layers']
    assert len(base['RootFS']['Layers']) == 83
    assert len(actual['RootFS']['Layers']) == 92
    assert manifest['phase1_build_evidence']['client_packet']['expected_sha256'] == PACKET_SHA
    assert manifest['phase1_build_evidence']['selected_custom_build']['product'] == '/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x'
    assert manifest['files']['/opt/wonad/notices/sources.tar.gz'] == SOURCES_SHA
    assert hashlib.sha256((OUT / 'sources.tar.gz').read_bytes()).hexdigest() == SOURCES_SHA
    expected = dict(User='demo', Entrypoint=['python3', '/opt/wonad/entrypoint.py'],
                    Cmd=None, WorkingDir='/state', StopSignal='SIGTERM')
    assert {key: actual['Config'].get(key) for key in expected} == expected
    print(json.dumps(dict(status='PASS',
        scope='root_actual_native5_immutable_image_full_offline_verifier_config_and_ancestry_not_runtime',
        image=IMAGE, manifest_sha256=MANIFEST_SHA, manifest_bytes=len(raw),
        manifest_canonical_sha256=module.manifest_digest(manifest),
        files=len(manifest['files']), base_image=base['Id'], base_layers=83,
        native_layers=92, configuration=expected, packet_sha256=PACKET_SHA,
        sources_sha256=SOURCES_SHA, runtime_qualified=False,
        initial_root_probe_disclosure='08b0b2 raised KeyError after successful verifier/manifest/ancestry checks because root guessed /opt/wonad/sources.tar.gz; the actual reviewed path is /opt/wonad/notices/sources.tar.gz; no product defect or publication mutation'),
        sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
