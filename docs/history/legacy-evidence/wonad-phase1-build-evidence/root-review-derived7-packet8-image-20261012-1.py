"""Independent immutable derived7 packaging audit; never starts Android."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

ROOT = Path('/u/elric/tree/wonad')
OUT = ROOT / 'android/out/phase1-conformance-candidate-custom7-5-7'
PARENT_OUT = ROOT / 'android/out/phase1-native-candidate-custom7-5-5'
IMAGE = 'sha256:e23259f2cd466b9635d4348c57ac07b0d02750ff89ca0b650b7dc3e45f79b772'
PARENT = 'sha256:0e425e724cb6f53cb1ef6ae080c39dfdfcf810b5e6fe7c262e419e2b750a01b4'
MANIFEST_SHA = 'e967bcd1c419935453f9f7d44176eca9a0eead42083ab9c3181bd37c20dc4b51'
PACKET_SHA = 'b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee'


def main():
    source = ROOT / 'android/container/build-phase1-conformance-candidate.py'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == 'c2719ce245bd68651401e46f92d09ecf2614629aa3eb07760f4fad24fd2dbebc'
    assert (OUT / 'built-image.id').read_text().strip() == IMAGE
    spec = importlib.util.spec_from_file_location('root_derived7_builder', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    actual, parent = module.inspect_image(IMAGE), module.inspect_image(PARENT)
    assert module.inspect_image('wonad:phase1-conformance-candidate-custom7-5-7')['Id'] == actual['Id'] == IMAGE
    module.validate_derived_image(parent, actual)
    raw = (OUT / 'manifest.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == MANIFEST_SHA
    manifest = json.loads(raw)
    module.validate_manifest(manifest)
    assert len(manifest['files']) == 59
    output = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none',
        '--read-only', '--tmpfs', '/tmp:rw,nosuid,size=64m', IMAGE, 'verify'], text=True, timeout=120)
    banner, separator, document = output.partition('\n')
    assert banner == 'Verifying fresh-guest Phase-1 conformance candidate…' and separator
    assert json.loads(document) == manifest
    subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--entrypoint', '/bin/sh', IMAGE, '-ec', 'test ! -e /opt/wonad/wonad.apk'], check=True, timeout=30)
    parent_manifest = json.loads((PARENT_OUT / 'manifest.json').read_bytes())
    bound_raw = (OUT / 'product-candidate-manifest.json').read_bytes()
    assert hashlib.sha256(bound_raw).hexdigest() == '27671c1fd130ddac1e7dfc95b0cd6398bbcdb29e9f9b7d9a9bea6124e0804678'
    assert json.loads(bound_raw) == parent_manifest
    assert manifest['base_product_candidate']['image_id'] == PARENT
    assert manifest['base_product_candidate']['manifest_sha256'] == module.canonical_sha256(parent_manifest)
    assert manifest['packet']['receipt_sha256'] == PACKET_SHA
    module.validate_phase1_base_evidence(parent_manifest,
        Path('/u/elric/tree/wonad-grapheneos-x86-custom-out-2026100600-5/target/product/emu64x'))
    for name, path in module.SOURCE_FILES.items():
        assert manifest['files']['/opt/wonad/phase1-conformance/' + name] == hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(dict(status='PASS',
        scope='root_actual_immutable_derived7_full_offline_verifier_manifest_ancestry_core_four_and_product_apk_absence_not_runtime',
        image=IMAGE, manifest_sha256=MANIFEST_SHA, manifest_bytes=len(raw),
        bound_native_manifest_sha256=hashlib.sha256(bound_raw).hexdigest(),
        parent_image=PARENT, native_layers=len(parent['RootFS']['Layers']),
        derived_layers=len(actual['RootFS']['Layers']),
        files=len(manifest['files']), packet_sha256=PACKET_SHA,
        configuration={key: actual['Config'].get(key) for key in ('User', 'Entrypoint', 'Cmd', 'WorkingDir', 'Labels')},
        core_four_current_source_equality=True, product_wonad_apk_absent=True,
        runtime_qualified=False), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
