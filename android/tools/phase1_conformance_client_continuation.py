"""External, prior-live-crypto admission; never starts Tools or admits a floor."""
from pathlib import Path
import phase1_conformance_version_chain as chain

require = chain.require
PARENT = '49ed1951686f5a3ada215f3d7d8f42fc9c943770f79cc144ee8875a9fb47d1d1'
EXTENSION = 'ce722ec7e08520641fdd8d758a7634917d93045c658b650cd6cea2d7edc6c98e'
CRYPTO = 'd39fd56d09d32f1e939fcfeb15984b143eff45c7dc0e1ff74b0fd7d1412512b6'

def authenticate(contract, continuation):
    """Return exact APK catalogue bytes, or None for unchanged default1/2.

    This first bounded admission accepts ONLY the externally reviewed immutable
    packet17 continuation and Root live proof. Runtime records still need the
    separate adjacent-install/canary/UID/whole-journal consumer.
    """
    if continuation is None:
        return None
    require(set(continuation) == {'schema','kind','extension','crypto_verification'} and
        type(continuation['schema']) is int and continuation['schema'] == 1 and
        continuation['kind'] == 'authenticated_version_continuation_v1', 'Continuation schema changed')
    ext = continuation['extension']; proof = continuation['crypto_verification']
    require(set(ext) == {'path','receipt'} and set(proof) == {'path','sha256','bytes'}, 'External descriptor changed')
    require(ext['receipt']['sha256'] == EXTENSION and proof['sha256'] == CRYPTO, 'Unreviewed continuation/crypto anchor')
    root = chain.packet.literal_existing(Path(ext['path']), directory=True)
    proof_path = chain.packet.literal_existing(Path(proof['path']), directory=False)
    require(proof_path.name == 'receipt.json', 'Exact crypto receipt required')
    before = chain.tree_fence(root)
    receipt, receipt_ref = chain.json_input(root/'receipt.json', ext['receipt'])
    crypto, _ = chain.json_input(proof_path, {k:proof[k] for k in ('sha256','bytes')})
    support = {}
    for key, name in (('log','verify.log'),('program','run.py'),('inputs_before','inputs-before.json'),('inputs_after','inputs-after.json')):
        support[key] = chain.read_verified(proof_path.parent/name, crypto[key])[0]
    import json
    parsed = lambda b: json.loads(b, object_pairs_hook=chain.packet.unique)
    inventories = parsed(support['inputs_before'])
    require(inventories == parsed(support['inputs_after']), 'Independent verification inputs changed')
    verdict = parsed(support['log'])
    require(type(crypto['exit_code']) is int and crypto['exit_code'] == 0 and
        type(crypto['began_monotonic_ns']) is int and type(crypto['ended_monotonic_ns']) is int and
        0 < crypto['began_monotonic_ns'] < crypto['ended_monotonic_ns'] and
        crypto['kind'] == 'root_independent_live_version_extension_verification' and
        crypto['live_tools_and_crypto_mocked'] is False and crypto['extension_receipt'] == receipt_ref,
        'Not the original successful live crypto invocation')
    parent_path = Path(contract['packet'])
    require(receipt['base_packet']['receipt']['sha256'] == PARENT and
        receipt['base_packet']['path'] == str(parent_path), 'Foreign parent packet')
    parent, _, parent_ref, values, parent_fence = chain.authenticate_parent(parent_path, PARENT)
    require(type(contract.get('packet_receipt')) is dict and
        set(contract['packet_receipt']) == {'sha256','bytes'}, 'External contract packet receipt required')
    chain.checked_ref(contract['packet_receipt'])
    require(contract['packet_receipt'] == parent_ref, 'External contract packet receipt differs from authenticated parent')
    require(receipt['sources'] == chain.source_contract(), 'Continuation verifier sources changed')
    argv = crypto['argv']
    require(type(argv) is list and len(argv) == 18 and all(type(x) is str for x in argv), 'Malformed original crypto argv')
    manifest_path = Path(argv[11])
    _, tools_ref = chain.authenticate_tools(manifest_path,
        receipt['tools']['manifest']['sha256'], receipt['tools']['image_id'])
    require(tools_ref == receipt['tools'], 'Original tools manifest bundle changed')
    require(argv[1:] == ['-B', str(Path(chain.__file__).resolve()), 'verify','--packet',str(parent),
        '--expected-packet-receipt-sha256', PARENT,'--tools-image',receipt['tools']['image_id'],
        '--tools-image-manifest',str(Path(argv[11])), '--tools-image-manifest-sha256',receipt['tools']['manifest']['sha256'],
        '--extension',str(root),'--expected-receipt-sha256',EXTENSION], 'Original crypto argv changed')
    # Original proof inventory binds the actual code and every immutable member;
    # unrelated subsequently changed host modules are not silently re-admitted.
    needed = [parent/'receipt.json', *[parent/p for p, ref in chain.packet.inventory(parent).items() if ref['bytes'] > 0],
        root/'receipt.json', *[root/p for p in receipt['files']], Path(chain.__file__).resolve()]
    for source in receipt['sources'].values():
        needed.append(Path(chain.__file__).resolve().parent/Path(source['tool']).name)
    for name in ('manifest.json','payload-inventory.json','source-packet-receipt.json',
            'source-packet-plan.json','Dockerfile','build-phase1-client-tools.py'):
        needed.append(manifest_path.parent/name)
    for path in needed:
        require(str(path) in inventories, 'Missing original input binding')
        chain.read_verified(path, inventories[str(path)])
    require(chain.packet.inventory(root) == {**receipt['files'], 'receipt.json':receipt_ref}, 'Extension inventory changed')
    values = chain.catalogue_bytes(root, values, receipt)
    require(chain.pair_proofs(values) == receipt['pair_proofs'], 'Actual base/adjacent APK proof changed')
    chain.validate_commands(receipt, values)
    require(verdict['receipt'] == receipt_ref and verdict['base_packet'] == receipt['base_packet'] and
        verdict['members'] == receipt['members'] and verdict['versions'] == [1,2,3,4] and
        verdict['runtime_qualified'] is False and verdict['new_compilation_claimed'] is False,
        'Crypto output/member binding changed')
    require(chain.tree_fence(root) == before and chain.tree_fence(parent) == parent_fence,
        'Input changed during continuation admission')
    chain.read_verified(proof_path, {k:proof[k] for k in ('sha256','bytes')})
    for key, name in (('log','verify.log'),('program','run.py'),('inputs_before','inputs-before.json'),('inputs_after','inputs-after.json')):
        require(chain.read_verified(proof_path.parent/name, crypto[key])[0] == support[key], 'Crypto support changed during admission')
    return {v: {'version_code':v, 'artifact':receipt['members'][str(v)]['file'],
        'package':'org.wonad.desktop', 'certificate_der_sha256':chain.packet.WONAD_CERT,
        'apk_bytes':values[v]} for v in (1,2,3,4)}
