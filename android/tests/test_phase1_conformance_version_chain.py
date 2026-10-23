"""Real immutable packet17/base+pair; MOCKED signing/SDK transport only.

Synthetic candidates copy an OLD signing block and are NOT valid signatures.
They are private unit fixtures, NEVER admissible artifacts or new compilation.
Actual structural/AXML/payload/source/receipt validators are not mocked.
"""
from pathlib import Path
import copy
import io
import json
import os
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import phase1_conformance_version_chain as chain

PACKET = Path("/u/elric/tree/wonad/android/out/phase1-emulator-client-packet-20261014-17")
PACKET_SHA = "49ed1951686f5a3ada215f3d7d8f42fc9c943770f79cc144ee8875a9fb47d1d1"
IMAGE = "sha256:f7ad3758f4913b44b320c252dfb1a6590aa34f6252a671b0db56fda3263889e1"
MANIFEST = Path("/u/elric/tree/wonad/android/out/phase1-client-tools-image-20261011-3/manifest.json")
MANIFEST_SHA = "3ac8bdf7330f8c0b9d8dbedfc97d9b58d9eaa295a2c91d9ad18f9fbcfa2b1dd6"


def synthetic_block_copy(unsigned):
    """Invalid crypto fixture, real APK structure; no keys/signing operation."""
    original = (PACKET/"conformance.apk").read_bytes()
    with zipfile.ZipFile(io.BytesIO(original)) as archive: central = archive.start_dir
    size = struct.unpack_from("<Q",original,central-24)[0]
    block = original[central-size-8:central]
    with zipfile.ZipFile(io.BytesIO(unsigned)) as archive: offset = archive.start_dir
    result = bytearray(unsigned[:offset]+block+unsigned[offset:])
    end = result.rfind(b"PK\x05\x06")
    struct.pack_into("<I",result,end+16,offset+len(block))
    return bytes(result)


class FakeTools:
    """Explicit external cryptographic/container boundary; no subprocesses."""
    instances = []; reject_verify = False; fail_sign = None; fail_cleanup = False; fail_close = False
    def __init__(self,image):
        self.image=image;self.container=None;self.token="b"*32;self.files={};self.roots=set();self.calls=[];self.count=0
        self.closed=False;self.instances.append(self)
    def __enter__(self):self.container="a"*64;return self
    def close(self):
        self.closed=True;self.container=None
        if self.fail_close:raise ValueError("synthetic container cleanup failure")
        self.files={};self.roots=set()
    def cp_in(self,source,target):self.files[target]=Path(source).read_bytes()
    def cp_out(self,source,target):chain.packet.write_new(target,self.files[source])
    def exec(self,*argv,env=None):
        if env is not None:raise AssertionError("No secret/environment fallback in this fixture")
        self.calls.append(list(argv))
        if argv[:2]==("mktemp","-d"):
            self.count+=1;root="/tmp/phase1-client-signing."+f"{self.count:08d}";self.roots.add(root);return root+"\n"
        if argv[:3]==("test","!","-e"):
            if argv[3] in self.roots:raise ValueError("synthetic surviving temporary root")
            return ""
        if argv[:2]==(chain.packet.CONTAINER_PYTHON,"-c"):
            if self.fail_cleanup:raise ValueError("synthetic session cleanup failure")
            root=argv[-1];names=sorted(p.rsplit("/",1)[1] for p in self.files if p.startswith(root+"/"))
            self.files={p:b for p,b in self.files.items() if not p.startswith(root+"/")};self.roots.remove(root)
            return json.dumps(names)
        if argv[0]==chain.packet.OPENSSL:
            self.files[argv[-1]]=b"SYNTHETIC NOT A PRIVATE KEY";return ""
        if argv[0]==chain.packet.ZIPALIGN:
            if "-f" in argv:self.files[argv[-1]]=self.files[argv[-2]]
            return ""
        if argv[:2]==(chain.packet.APKSIGNER,"sign"):
            if self.fail_sign is not None:raise self.fail_sign
            self.files[argv[argv.index("--out")+1]]=synthetic_block_copy(self.files[argv[-1]])
            return ""
        if argv[:2]==(chain.packet.APKSIGNER,"verify"):
            if self.reject_verify:raise ValueError("synthetic live crypto rejects invalid OLD signature")
            return "Verified using v3 scheme (APK Signature Scheme v3): true\nSigner #1 certificate SHA-256 digest: "+chain.packet.WONAD_CERT+"\n"
        if argv[:3]==(chain.packet.AAPT2,"dump","badging"):
            with zipfile.ZipFile(io.BytesIO(self.files[argv[-1]])) as archive:
                version=chain.binary.manifest_version(archive.read("AndroidManifest.xml"))["version"]
            return f"package: name='org.wonad.desktop' versionCode='{version}' versionName='3.0-phase1-conformance'\n"
        if argv[:3]==(chain.packet.AAPT2,"dump","xmltree"):
            return 'android:targetPackage="org.wonad.desktop"\n'
        raise AssertionError("Unreviewed synthetic boundary: "+repr(argv))


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix="wonad-version-chain-SYNTHETIC-");self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.signer=self.root/"FAKE-NONKEY";self.signer.mkdir()
        public=(PACKET/"evidence/certificates/wonad.x509.pem").read_bytes()
        (self.signer/"certificate.x509.pem").write_bytes(public)
        (self.signer/"private.pem").write_bytes(b"SYNTHETIC NOT A REAL KEY\n");(self.signer/"private.pem").chmod(0o600)
        self.args=SimpleNamespace(packet=PACKET,expected_packet_receipt_sha256=PACKET_SHA,tools_image=IMAGE,
            tools_image_manifest=MANIFEST,tools_image_manifest_sha256=MANIFEST_SHA,output=self.root/"synthetic-extension",
            signer=self.signer,public_cert=self.signer/"certificate.x509.pem",allow_development_signing=True)
        FakeTools.instances=[];FakeTools.reject_verify=False;FakeTools.fail_sign=None;FakeTools.fail_cleanup=False;FakeTools.fail_close=False
        self.addCleanup(self.reset_boundary)
    def reset_boundary(self):
        FakeTools.reject_verify=False;FakeTools.fail_sign=None;FakeTools.fail_cleanup=False;FakeTools.fail_close=False
    def fixture(self):
        with patch.object(chain.packet,"Tools",FakeTools):result=chain.prepare(self.args)
        self.path=self.args.output;self.receipt=json.loads((self.path/"receipt.json").read_bytes())
        self.verify_args=SimpleNamespace(**{k:v for k,v in vars(self.args).items() if k not in {"output","signer","public_cert","allow_development_signing"}},
            extension=self.path,expected_receipt_sha256=result["receipt"]["sha256"])
        return result
    def reseal(self):
        (self.path/"receipt.json").write_bytes(chain.packet.canonical(self.receipt))
        self.verify_args.expected_receipt_sha256=chain.read_verified(self.path/"receipt.json")[1]["sha256"]
    def reject(self,pattern=None):
        with patch.object(chain.packet,"Tools",FakeTools),self.assertRaisesRegex(ValueError,pattern or "."):
            chain.verify(self.verify_args)
    def disposed(self,argv,**kwargs):
        self.assertEqual(argv,["docker","container","inspect","a"*64])
        return SimpleNamespace(returncode=1,stdout="[]\n",stderr="Error: No such container: "+"a"*64)

    def test_real_packet_plan_never_reads_key_signs_or_creates_output(self):
        (self.signer/"private.pem").unlink()
        result,_=chain.plan(self.args)
        self.assertEqual(result["targets"],[3,4]);self.assertFalse(result["new_compilation_claimed"])
        self.assertFalse(self.args.output.exists());self.assertEqual(FakeTools.instances,[])

    def test_signing_requires_explicit_authorization_before_any_custody(self):
        self.args.allow_development_signing=False
        with self.assertRaisesRegex(ValueError,"authorization"):chain.prepare(self.args)
        self.assertFalse(self.args.output.exists());self.assertEqual(FakeTools.instances,[])

    def test_actual_builder_and_verifier_with_explicit_crypto_double(self):
        self.fixture()
        with patch.object(chain.packet,"Tools",FakeTools),patch.object(chain.subprocess,"run",side_effect=self.disposed):
            verdict=chain.verify(self.verify_args)
        self.assertFalse(verdict["runtime_qualified"]);self.assertFalse(verdict["new_compilation_claimed"])
        self.assertEqual(set(self.receipt["pair_proofs"]),{"1->3","1->4","2->3","3->4"})
        self.assertTrue(all(t.closed and not t.roots for t in FakeTools.instances))
        self.assertEqual(chain.read_verified(PACKET/"receipt.json")[1]["sha256"],PACKET_SHA)
        self.assertEqual(self.receipt["sources"]["packet"]["sha256"],chain.packet.sha(Path(chain.packet.__file__)))

    def test_structural_fixture_cannot_skip_live_crypto_gate(self):
        self.fixture();FakeTools.reject_verify=True
        with patch.object(chain.subprocess,"run",side_effect=self.disposed):
            self.reject("crypto rejects")

    def test_external_parent_and_extension_pins_are_mandatory(self):
        self.args.expected_packet_receipt_sha256="0"*64
        with self.assertRaisesRegex(ValueError,"external packet"):chain.plan(self.args)
        self.args.expected_packet_receipt_sha256=PACKET_SHA;self.fixture()
        self.verify_args.expected_receipt_sha256="0"*64;self.reject("external pin")

    def test_fresh_output_and_canonical_parent_required(self):
        self.args.output.mkdir()
        with self.assertRaisesRegex(ValueError,"fresh literal"):chain.plan(self.args)
        alias=self.root/"packet-alias";alias.symlink_to(PACKET,target_is_directory=True);self.args.packet=alias
        with self.assertRaisesRegex(ValueError,"literal"):chain.plan(self.args)

    def test_foreign_public_signer_or_tools_pin_rejected(self):
        self.args.tools_image_manifest_sha256="0"*64
        with self.assertRaisesRegex(ValueError,"Tools manifest"):chain.plan(self.args)
        self.args.tools_image_manifest_sha256=MANIFEST_SHA
        (self.signer/"certificate.x509.pem").write_bytes((PACKET/"evidence/certificates/fixture.x509.pem").read_bytes())
        with self.assertRaisesRegex(ValueError,"DEV certificate"):chain.plan(self.args)

    def test_missing_adjacent_and_changed_manifest_proofs_rejected(self):
        self.fixture();original=copy.deepcopy(self.receipt)
        del self.receipt["pair_proofs"]["3->4"];self.reseal();self.reject("binary proof")
        self.receipt=original;self.receipt["pair_proofs"]["1->3"]["candidate"]["manifest"]["normalized_sha256"]="0"*64
        self.reseal();self.reject("binary proof")

    def test_typed_versions_refs_and_parent_members_cannot_be_relabelled(self):
        self.fixture();original=copy.deepcopy(self.receipt)
        mutations=(lambda r:r["versions"].__setitem__(0,True),
            lambda r:r["members"]["1"].__setitem__("parent_member",True),
            lambda r:r["files"]["members/v3.apk"].__setitem__("bytes",float(r["files"]["members/v3.apk"]["bytes"])))
        for change in mutations:
            self.receipt=copy.deepcopy(original);change(self.receipt);self.reseal();self.reject()

    def test_no_key_generation_failed_commands_or_cleanup_waiver(self):
        self.fixture();original=copy.deepcopy(self.receipt)
        mutations=(lambda r:r["signing"]["3"]["commands"][0]["argv"].__setitem__(1,"genrsa"),
            lambda r:r["signing"]["3"].__setitem__("temporary_private_key_removed",False),
            lambda r:r["inspections"]["4"]["commands"][0].__setitem__("returncode",True),
            lambda r:r["inspections"]["3"]["commands"][0].__setitem__("stdout_sha256","0"*64))
        for change in mutations:
            self.receipt=copy.deepcopy(original);change(self.receipt);self.reseal();self.reject()

    def test_changed_unsigned_extra_file_and_receipt_source_rejected(self):
        self.fixture();unsigned=self.path/"unsigned/v3.apk";raw=unsigned.read_bytes();unsigned.write_bytes(raw+b"extra")
        self.reject("extension files");unsigned.write_bytes(raw)
        (self.path/"unexpected.txt").write_text("original")
        self.receipt["files"]["unexpected.txt"]=chain.read_verified(self.path/"unexpected.txt")[1];self.reseal()
        self.reject("artifact set")

    def test_failure_evidence_retains_primary_and_owned_cleanup(self):
        primary=ValueError("original synthetic signing failure");FakeTools.fail_sign=primary
        with patch.object(chain.packet,"Tools",FakeTools),self.assertRaises(ValueError) as observed:chain.prepare(self.args)
        self.assertIs(observed.exception,primary)
        self.assertEqual(json.loads((self.args.output/"failure.json").read_text())["status"],"failed_extension_not_qualified")
        self.assertFalse((self.args.output/"receipt.json").exists())
        self.assertTrue(FakeTools.instances[-1].closed);self.assertEqual(FakeTools.instances[-1].roots,set())

    def test_secondary_tools_cleanup_cannot_mask_primary(self):
        primary=ValueError("original failure");FakeTools.fail_close=True
        with patch.object(chain.packet,"Tools",FakeTools),self.assertRaises(ValueError) as observed:
            with chain.owned_tools(IMAGE):raise primary
        self.assertIs(observed.exception,primary);self.assertTrue(any("cleanup" in n for n in primary.__notes__))

    def test_secondary_failure_sealing_cannot_mask_primary(self):
        primary=ValueError("original synthetic signing failure");FakeTools.fail_sign=primary
        original=chain.packet.write_new
        def fail_seal(path,*args,**kwargs):
            if Path(path).name=="failure.json":raise OSError("synthetic evidence disk failure")
            return original(path,*args,**kwargs)
        with patch.object(chain.packet,"Tools",FakeTools),patch.object(chain.packet,"write_new",side_effect=fail_seal),self.assertRaises(ValueError) as observed:
            chain.prepare(self.args)
        self.assertIs(observed.exception,primary);self.assertTrue(any("sealing" in n for n in primary.__notes__))
        self.assertTrue(FakeTools.instances[-1].closed)

    def test_secondary_session_cleanup_cannot_mask_primary(self):
        primary=ValueError("original synthetic signing failure")
        FakeTools.fail_sign=primary;FakeTools.fail_cleanup=True
        with patch.object(chain.packet,"Tools",FakeTools),self.assertRaises(ValueError) as observed:chain.prepare(self.args)
        self.assertIs(observed.exception,primary)
        self.assertTrue(any("cleanup" in n for n in primary.__notes__))
        self.assertTrue(FakeTools.instances[-1].closed)

    def test_original_tools_epoch_must_be_actually_absent(self):
        epoch={"container_id":"a"*64}
        with patch.object(chain.subprocess,"run",return_value=SimpleNamespace(returncode=0,stdout='[{"State":{"Running":false}}]',stderr="")),self.assertRaisesRegex(ValueError,"still exists"):
            chain.observe_disposed_tools(epoch)
        with patch.object(chain.subprocess,"run",return_value=SimpleNamespace(returncode=True,stdout="[]",stderr="No such container")),self.assertRaises(ValueError):
            chain.observe_disposed_tools(epoch)
        with patch.object(chain.subprocess,"run",return_value=SimpleNamespace(returncode=1,stdout="[]",stderr="No such container: "+"c"*64)),self.assertRaises(ValueError):
            chain.observe_disposed_tools(epoch)

    def tools_copy(self):
        root=self.root/"tools-bundle";root.mkdir()
        for name in ("manifest.json","payload-inventory.json","source-packet-receipt.json","source-packet-plan.json","Dockerfile","build-phase1-client-tools.py"):
            (root/name).write_bytes((MANIFEST.parent/name).read_bytes())
        return root/"manifest.json"

    def test_tools_bundle_modify_restore_during_legacy_gate_rejected(self):
        path=self.tools_copy();original=chain.packet.authenticate_tools_image_manifest
        def raced(*args):
            value=original(*args);target=path.parent/"payload-inventory.json";body=target.read_bytes()
            target.write_bytes(body+b"\n");target.write_bytes(body)
            return value
        with patch.object(chain.packet,"authenticate_tools_image_manifest",side_effect=raced),self.assertRaisesRegex(ValueError,"changed"):
            chain.authenticate_tools(path,MANIFEST_SHA,IMAGE)

    def test_tools_parsed_manifest_must_equal_original_verified_bytes(self):
        path=self.tools_copy();original=chain.packet.authenticate_tools_image_manifest
        def drift(*args):
            value=original(*args);value["manifest"]["scope"]="foreign parsed scope";return value
        with patch.object(chain.packet,"authenticate_tools_image_manifest",side_effect=drift),self.assertRaisesRegex(ValueError,"bundle changed"):
            chain.authenticate_tools(path,MANIFEST_SHA,IMAGE)


class StableReadTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix="wonad-version-chain-read-");self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.path=self.root/"raw";self.path.write_bytes(b"original")
    def test_symlink_hardlink_empty_and_wrong_typed_reference_rejected(self):
        alias=self.root/"alias";alias.symlink_to(self.path)
        with self.assertRaises(ValueError):chain.read_verified(alias)
        os.link(self.path,self.root/"hardlink")
        with self.assertRaises(ValueError):chain.read_verified(self.path)
        (self.root/"hardlink").unlink();self.path.write_bytes(b"")
        with self.assertRaises(ValueError):chain.read_verified(self.path)
        self.path.write_bytes(b"original");_,ref=chain.read_verified(self.path);ref["bytes"]=8.0
        with self.assertRaises(ValueError):chain.read_verified(self.path,ref)
    def test_read_phase_modify_restore_rejected(self):
        original=os.read;changed=False
        def raced(descriptor,count):
            nonlocal changed
            data=original(descriptor,count)
            if not changed:
                changed=True;self.path.write_bytes(b"changed!");self.path.write_bytes(b"original")
            return data
        with patch.object(chain.os,"read",side_effect=raced),self.assertRaisesRegex(ValueError,"changed"):
            chain.read_verified(self.path)


if __name__=="__main__":unittest.main(verbosity=2)
