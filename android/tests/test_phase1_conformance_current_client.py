"""Genuine packet17 bytes; synthetic transport, never guest/runtime proof.

No signature/tool parser is mocked. Root's separate full live-tools packet
verification remains the cryptographic/compiler gate; this suite reuses its
out-of-band original receipt pin and actual binary version-only pair parser.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace, MethodType
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "tools")]
import phase1_conformance_current_client as client
from phase1_conformance_common import canonical, file_ref

PACKET = Path(os.environ.get("WONAD_TEST_CURRENT_PACKET", "/u/elric/tree/wonad/android/out/phase1-emulator-client-packet-20261014-17"))
RECEIPT = os.environ.get("WONAD_TEST_CURRENT_PACKET_RECEIPT", "49ed1951686f5a3ada215f3d7d8f42fc9c943770f79cc144ee8875a9fb47d1d1")
UID = 10180


class Transport:
    """Original-shaped raw command rows; returned values are explicit doubles."""
    def __init__(self, output):
        self.output = output; self.trace = []; self.uids = {client.APP: UID}
        self.container = "a" * 64
        self.sampler_identity = {"container_id": self.container, "image_id": "sha256:" + "b" * 64,
            "boot_id": "12345678-1234-1234-1234-123456789abc", "fingerprint": "synthetic-current-client-test",
            "container_run": "c" * 32, "userdata_path": str(output / "state"), "user": "1000:1000", "kvm_group": "103", "container_pid": 777}
        self.version = 1; self.apk = PACKET / "conformance.apk"; self.reverse_shared = False
        self.prefix = ["docker", "exec", self.container, "adb", "-s", client.SERIAL]

    def write(self, relative, argv, payload):
        path = self.output / relative; path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists(): raise AssertionError("Synthetic transport must never overwrite")
        began = time.monotonic_ns(); path.write_bytes(payload)
        self.trace.append({"sequence": len(self.trace), "kind": "command", "argv": argv, "returncode": 0,
            "evidence": relative, "output_sha256": hashlib.sha256(payload).hexdigest(),
            "started_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()})
        return payload.decode(errors="replace").strip()

    def read(self, relative, *args):
        args = tuple(map(str,args))
        if args[:6] == ("pm", "list", "packages", "-U", "--user", "0"):
            raw = f"package:{client.APP} uid:{UID}\n"
            if "--uid" in args and self.reverse_shared: raw += f"package:org.foreign uid:{UID}\n"
        elif args == ("pm", "path", "--user", "0", client.APP): raw = "package:/data/app/current/base.apk\n"
        elif args == ("dumpsys", "package", client.APP):
            raw = f"Package [{client.APP}] (123a):\n appId={UID}\n versionCode={self.version} minSdk=35\n" + \
                " flags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]\n pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]\n privatePkgFlags=[ ]\n User 0: installed=true hidden=false\n"
        else: raise AssertionError(args)
        return self.write(relative, self.prefix + ["shell", *args], raw.encode())

    def adb(self, *args, evidence, binary):
        assert args == ("exec-out", "cat", "/data/app/current/base.apk") and binary
        return self.write(evidence, self.prefix + list(args), self.apk.read_bytes())


class CurrentClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = {"packet": str(PACKET), "packet_receipt": file_ref(PACKET / "receipt.json")}
        if cls.contract["packet_receipt"]["sha256"] != RECEIPT: raise AssertionError("Original packet17 trusted receipt changed")
        cls.members = client.catalogue(cls.contract, include_successor=True)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="wonad-current-client-raw-")
        self.addCleanup(self.directory.cleanup); self.root = Path(self.directory.name)
        self.p = Transport(self.root); self.identity = self.p.sampler_identity
        self.actor = SimpleNamespace(test=self.p, contract=self.contract, prefix="client-transitions/first", action={"client_observations":[]})
        self.actor.raw_read = self.p.read
        self.current = client.current_client_for(self.p, self.contract)

    def marker(self, mode, version):
        seed = self.seed
        values = {"update_marker":"passed", "mode":mode, "run":seed["run"], "owner_uid":str(UID), "version_code":str(version),
            "nonce_sha256":hashlib.sha256(seed["nonce"].encode()).hexdigest(), "fingerprint":self.identity["fingerprint"],
            "native_abi":"x86_64", "existed":"true"}
        return ("".join(f"INSTRUMENTATION_RESULT: {key}={value}\n" for key,value in values.items()) + "INSTRUMENTATION_CODE: -1\n").encode()

    def canary(self, label):
        from phase1_conformance_soak_apk_update_acceptance import canary_argv
        package = "org.wonad.desktop.test"; prefix = "client-transitions/first/" + label
        files = {"path":prefix+"-canary-path.txt", "apk":prefix+"-canary.apk"}
        self.p.write(files["path"],self.p.prefix+["shell","pm","path","--user","0",package],b"package:/data/app/canary/base.apk\n")
        self.p.write(files["apk"],self.p.prefix+["exec-out","cat","/data/app/canary/base.apk"],(PACKET/"security.apk").read_bytes())
        mode = "create" if label == "before" else "read"; relative = prefix+"-marker.txt"
        self.p.write(relative,self.p.prefix+canary_argv([],self.seed,mode),self.marker(mode,1 if mode=="create" else 2))
        return files,relative

    def forward(self):
        self.seed={"run":"d"*32,"nonce":"e"*32}
        before_canary,create = self.canary("before")
        before = client.read_member(self.actor,"before",self.members[1],UID)
        install = "client-transitions/first/install.txt"
        self.p.write(install,self.p.prefix+["install","-r","--user","0",client.UPDATE_BUNDLE],b"Success\n")
        self.p.version=2;self.p.apk=PACKET/"conformance-version-update/candidate.apk"
        after_canary,read = self.canary("after")
        after = client.read_member(self.actor,"after",self.members[2],UID)
        value={"schema":1,"kind":client.TRANSITION_KIND,"status":client.TRANSITION_STATUS,"identity":self.identity,
            "packet_receipt":self.contract["packet_receipt"],"sources":client.source_contract(),"parent":None,"from_version":1,"to_version":2,
            "uid":UID,"before":before,"after":after,"install":install,"seed":{**self.seed,"create":create,"read":read,
                "canary_before":before_canary,"canary_after":after_canary},"runtime_qualified":False,"whole_campaign_complete":False}
        path=self.root/"client-transitions/first/forward-only.json";path.write_bytes(canonical(value))
        self.forward_path,self.forward_value=path,value
        return path

    def admit(self):
        path=self.forward();self.current.advance_forward(path,file_ref(path));return self.current.selection()

    def test_genuine_pair_and_exact_typed_version2_observations(self):
        value=self.admit();self.assertEqual(value["member"]["version_code"],2)
        self.assertEqual(value["member"]["artifact"],file_ref(self.p.apk))
        self.assertEqual(value["member"]["certificate_der_sha256"],self.members[1]["certificate_der_sha256"])
        for scenario in ("credential_key","user_switch","frozen_client","client_death","malformed_calls"):
            self.actor.prefix="observations/"+scenario;self.actor.action={"client_observations":[]}
            self.assertEqual(self.current.observe(self.actor,"before"),value)
        self.assertEqual(len(self.p.trace), len({row["sequence"] for row in self.p.trace}))

    def test_version_selector_cannot_advance_without_new_forward_record(self):
        self.p.version=2;self.p.apk=PACKET/"conformance-version-update/candidate.apk"
        with self.assertRaisesRegex(ValueError,"Installed version"):
            self.current.observe(self.actor,"unadmitted")

    def test_old_update_restore_kind_is_not_new_surviving_floor(self):
        path=self.forward();value=self.forward_value;value["kind"]="phase1_policy_free_same_guest_apk_update_restore_action_v1"
        path.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError,"new authenticated forward-only"):
            self.current.advance_forward(path,file_ref(path))

    def test_downgrade_or_restore_later_in_whole_journal_rejected(self):
        self.admit()
        self.p.write("later-restore.txt",self.p.prefix+["install","-r","-d","--user","0",client.BASE_BUNDLE],b"Success\n")
        with self.assertRaisesRegex(ValueError,"restore/downgrade/reset"):
            self.current.selection()

    def test_reset_alias_later_in_whole_journal_rejected(self):
        self.admit()
        self.p.write("later-clear.txt",self.p.prefix+["shell","pm","clear",client.APP],b"Success\n")
        with self.assertRaisesRegex(ValueError,"restore/downgrade/reset"):
            self.current.selection()

    def test_unknown_same_signer_payload_install_cannot_hide_in_journal(self):
        self.admit()
        self.p.write("later-unknown.txt",self.p.prefix+["install","-r","--user","0","/data/local/tmp/unknown.apk"],b"Success\n")
        with self.assertRaisesRegex(ValueError,"restore/downgrade/reset"):
            self.current.selection()

    def test_shell_reset_wrapper_rejected(self):
        self.admit()
        self.p.write("later-wrapper.txt",self.p.prefix+["shell","sh","-c","pm clear org.wonad.desktop"],b"Success\n")
        with self.assertRaisesRegex(ValueError,"restore/downgrade/reset"):
            self.current.selection()

    def test_stale_base_payload_at_reported_version2_rejected(self):
        self.admit();self.p.apk=PACKET/"conformance.apk"
        with self.assertRaisesRegex(ValueError,"exact authenticated current member"):
            self.current.observe(self.actor,"stale-base")

    def test_foreign_payload_and_signer_rejected(self):
        self.admit();self.p.apk=PACKET/"wrong-signer/wrong-wonad.apk"
        with self.assertRaisesRegex(ValueError,"exact authenticated current member"):
            self.current.observe(self.actor,"foreign")

    def test_reverse_uid_requires_unique_exact_target(self):
        self.admit();self.p.reverse_shared=True
        with self.assertRaisesRegex(ValueError,"Shared/foreign initial client UID"):
            self.current.observe(self.actor,"shared")

    def test_original_uid_cannot_reset_between_scenarios(self):
        self.admit();self.p.uids[client.APP]=10181
        with self.assertRaisesRegex(ValueError,"owner/UID reset"):
            self.current.selection()

    def test_same_owner_admission_object_cannot_be_relabelled(self):
        self.admit()
        with self.assertRaisesRegex(ValueError,"reset/relabel"):
            client.current_client_for(self.p,self.contract,client.CurrentClient(self.p,self.contract))

    def test_replayed_forward_record_and_versions3plus_need_real_successor_chain(self):
        self.admit()
        with self.assertRaisesRegex(ValueError,"successor chain for versions3"):
            self.current.advance_forward(self.forward_path,file_ref(self.forward_path))

    def test_resealed_forward_record_fails_original_external_hash(self):
        self.admit();self.forward_value["uid"]=10181;self.forward_path.write_bytes(canonical(self.forward_value))
        with self.assertRaisesRegex(ValueError,"changed/resealed"):
            self.current.selection()

    def test_typed_version_and_uid_fields_are_not_booleans(self):
        path=self.forward();value=self.forward_value;value["from_version"]=True;path.write_bytes(canonical(value))
        with self.assertRaisesRegex(ValueError,"forward-only"):
            self.current.advance_forward(path,file_ref(path))

    def test_unexpected_existing_observation_is_preserved(self):
        self.actor.prefix="unexpected";path=self.root/"unexpected/current-client/before.apk"
        path.parent.mkdir(parents=True);path.write_bytes(b"user-owned-existing")
        with self.assertRaisesRegex(ValueError,"Never overwrite"):
            self.current.observe(self.actor,"before")
        self.assertEqual(path.read_bytes(),b"user-owned-existing")

    def test_observation_parent_alias_is_rejected_before_any_read(self):
        self.actor.prefix="alias";(self.root/"alias").symlink_to(self.root,target_is_directory=True)
        original=len(self.p.trace)
        with self.assertRaisesRegex(ValueError,"Unexpected observer parent"):
            self.current.observe(self.actor,"before")
        self.assertEqual(len(self.p.trace),original)

    def test_original_start_runtime_body_records_a_started_only_point(self):
        import phase1_conformance_clean_boot as lane
        p = SimpleNamespace(instrument=None, instrument_path=self.root/"actual-point"/"held.txt",
            container=self.p.container, conformance_run="f"*32, initial_nonce="e"*32, trace=[],
            wait_runtime_ready=lambda: True, wait=lambda *args, **kwargs: True)
        p._record = MethodType(lane.Producer._record, p)
        with patch.object(lane.subprocess,"Popen",return_value=SimpleNamespace(pid=123)) as popen:
            self.assertTrue(lane.Producer.start_runtime(p))
        p.instrument_file.close()
        row = p.trace[0]
        self.assertNotIn("ended_monotonic_ns",row);self.assertNotIn("host_pid",row)
        self.assertEqual(row["argv"],popen.call_args.args[0])
        client.checked_trace(p.trace,self.identity)
        self.assertEqual(client.target_mutations(p.trace,self.identity),[])
        for key,value in (("ended_monotonic_ns",row["started_monotonic_ns"]+1),("argv",[*row["argv"][:-1],"org.foreign/.Runner"]),
            ("host_pid",123),("started_monotonic_ns",True),("id","instrumentation-"+"0"*32)):
            changed={**row,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError):client.checked_trace([changed],self.identity)

    def test_real_noncommand_uid_combine_is_not_a_clock_or_executable_escape(self):
        import phase1_conformance_recents as mechanics
        p=SimpleNamespace(trace=[]);p._record=MethodType(mechanics.Producer._record,p)
        for index in range(6):
            p._record({"kind":"command","argv":self.p.prefix+["shell","pm","list","packages","-U","--user","0",client.APP],
                "returncode":0,"started_monotonic_ns":10+index*2,"ended_monotonic_ns":11+index*2})
        p._record({"kind":"derived","inputs":list(range(6)),"evidence":"identity/package-uids.txt","output_sha256":"a"*64})
        client.checked_trace(p.trace,self.identity)
        for field,value in (("inputs",[0,1,2,3,4,4]),("argv",self.p.prefix+["shell","pm","clear",client.APP]),
            ("evidence","unreviewed-derived.txt"),("started_monotonic_ns",100)):
            changed=copy.deepcopy(p.trace);changed[-1][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,"non-command"):client.checked_trace(changed,self.identity)

    def test_intervals_cannot_use_point_event_missing_end_exception(self):
        self.p.write("interval.txt",self.p.prefix+["shell","am","get-current-user"],b"0\n")
        for kind in ("command","owned_test_credential","background_finish"):
            row={**self.p.trace[0],"kind":kind};row.pop("ended_monotonic_ns")
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,"Untyped/reordered"):client.checked_trace([row],self.identity)

    def test_exact_broker_death_arm_is_seven_fields_not_generic_phase(self):
        prefix=self.p.prefix+["shell","dumpsys","activity","--user","0","service",client.runtime.SERVICE,
            "runtime-command","1"*32,"2"*32,"expect-broker-death"]
        self.assertTrue(client.reviewed_command(prefix+["77","88"],self.identity))
        for tail in ([],["77"],["77","88","5"],["0","88"],["77","true"],["-77","88"]):
            with self.subTest(tail=tail):self.assertFalse(client.reviewed_command(prefix+tail,self.identity))

    def test_secondary_home_resolution_is_exact_bounded_read_not_package_mutator(self):
        prefix=self.p.prefix+["shell","cmd","package","resolve-activity","--brief","--user"]
        suffix=["-a","android.intent.action.MAIN","-c","android.intent.category.HOME"]
        for user in ("0","10","1000"):self.assertTrue(client.reviewed_command(prefix+[user,*suffix],self.identity))
        for args in (["1001",*suffix],["true",*suffix],["10",*suffix,"--clear-data"],["10","-a","foreign.ACTION","-c","android.intent.category.HOME"]):
            with self.subTest(args=args):self.assertFalse(client.reviewed_command(prefix+args,self.identity))

    def test_closed_journal_grammar_rejects_aliases_and_owned_container_wrappers(self):
        self.admit()
        aliases=[self.p.prefix+["shell","/system/bin/pm","clear",client.APP],
            ["docker","exec",self.p.container,"sh","-c","adb -s emulator-5580 shell pm clear org.wonad.desktop"],
            self.p.prefix+["shell","su","0","sh","-c","pm clear org.wonad.desktop"],
            self.p.prefix+["shell","cmd","package","clear",client.APP],
            self.p.prefix+["shell","/system/bin/cmd","package","clear",client.APP],
            ["docker","exec",self.p.container,"env","adb","-s",client.SERIAL,"shell","pm","clear",client.APP],
            self.p.prefix+["shell","am","force-stop",client.APP],
            self.p.prefix+["shell","dumpsys","package",client.APP,"--clear-data"],
            self.p.prefix+["shell","su","0","kill","-CONT","505;pm clear org.wonad.desktop"],
            ["docker","exec",self.p.container,"rm","-rf","--","/data"],
            self.p.prefix+["shell","input","keyboard","-d","0","text","pm clear org.wonad.desktop"]]
        original=len(self.p.trace)
        for index,argv in enumerate(aliases):
            self.p.write(f"alias-{index}.txt",argv,b"Success\n")
            with self.subTest(argv=argv),self.assertRaisesRegex(ValueError,"restore/downgrade/reset"):self.current.selection()
            del self.p.trace[original:]

    def test_raw_and_json_parse_the_same_verified_bytes_not_file_ref_then_path_read(self):
        relative="same-read.txt";suffix=("shell","am","get-current-user")
        self.p.write(relative,self.p.prefix+list(suffix),b"0\n")
        with patch.object(client,"file_ref",side_effect=AssertionError("Separate hash/read prohibited")):
            self.assertEqual(client.raw(self.root,self.p.trace,self.identity,relative,suffix),("0\n",0))
        path=self.root/"same-read.json";path.write_bytes(b'{"original":true}')
        expected=file_ref(path)
        with patch.object(client,"file_ref",side_effect=AssertionError("Separate hash/read prohibited")):
            self.assertEqual(client.verified_json(path,expected),{"original":True})

    def test_mutation_during_original_descriptor_read_fails_even_when_old_bytes_are_returned(self):
        path=self.root/"mutating.json";path.write_bytes(b'{"original":true}')
        expected=file_ref(path);original_read=client.os.read;changed=False
        def mutate(fd,size):
            nonlocal changed
            value=original_read(fd,size)
            if not changed:
                changed=True;path.write_bytes(b'{"changed":false}')
            return value
        with patch.object(client.os,"read",side_effect=mutate),self.assertRaisesRegex(ValueError,"changed during read"):
            client.verified_json(path,expected)

    def test_original_evidence_rejects_links_empty_bytes_duplicate_json_and_boolean_size(self):
        path=self.root/"unique.json";path.write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(ValueError):client.verified_json(path,file_ref(path))
        path.write_bytes(b'{}');expected=file_ref(path)
        with self.assertRaisesRegex(ValueError,"changed/resealed"):client.verified_bytes(path,{"sha256":expected["sha256"],"bytes":True})
        alias=self.root/"alias.json";alias.symlink_to(path)
        with self.assertRaisesRegex(ValueError,"Aliased"):client.verified_json(alias,expected)
        link=self.root/"link.json";os.link(path,link)
        with self.assertRaisesRegex(ValueError,"unique regular"):client.verified_json(path,expected)
        empty=self.root/"empty.json";empty.touch()
        with self.assertRaisesRegex(ValueError,"nonempty"):client.verified_bytes(empty)


if __name__=="__main__":unittest.main(verbosity=2)
