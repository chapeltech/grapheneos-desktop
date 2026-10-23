#!/usr/bin/env python3
"""Separate DEV version-only continuation; never reseals its parent packet.

Only genuine signed3/4 + live pinned-tool verification can qualify this
extension. Structural fixtures cannot admit a current installed version.
"""
import argparse
from contextlib import contextmanager, ExitStack
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import phase1_emulator_client_packet as packet
import native_apk_update_smoke as derivation
import native_apk_update_acceptance as binary
import native_wrong_signer_acceptance as signer_structure

KIND = "phase1_conformance_version_chain_extension_v1"
STATUS = "signed_version_only_derived_not_runtime_qualified"
TARGETS = (3, 4)
PAIRS = ((1, 3), (1, 4), (2, 3), (3, 4))
MAX_BYTES = 128 * 1024 * 1024
require = packet.require


@contextmanager
def unchanged_file(path):
    """Linux mutation watcher catches modify+restore even on coarse clocks."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.inotify_init1.argtypes = [ctypes.c_int]; libc.inotify_init1.restype = ctypes.c_int
    libc.inotify_add_watch.argtypes = [ctypes.c_int,ctypes.c_char_p,ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int
    descriptor = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    require(descriptor >= 0, "Cannot establish fail-closed input mutation watch")
    try:
        # MODIFY, ATTRIB, CLOSE_WRITE, MOVE_SELF, DELETE_SELF, UNMOUNT;
        # DONT_FOLLOW. Overflow/ignored events also produce nonempty bytes.
        watch = libc.inotify_add_watch(descriptor,os.fsencode(path),0x2|0x4|0x8|0x800|0x400|0x2000|0x02000000)
        require(watch >= 0, "Cannot watch exact input inode")
        yield
        try: events = os.read(descriptor,65536)
        except BlockingIOError: events = b""
        require(events == b"", "Input changed during verified read (kernel mutation event)")
    finally: os.close(descriptor)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def checked_ref(value):
    require(type(value) is dict and set(value) == {"sha256", "bytes"} and
        type(value["sha256"]) is str and packet.SHA256.fullmatch(value["sha256"]) and
        type(value["bytes"]) is int and value["bytes"] > 0, "Exact typed content reference required")
    return value


def read_verified(path, expected=None):
    """Hash and parse the SAME nofollow stable bytes; reject modify+restore."""
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "Aliased evidence ancestry")
    with unchanged_file(path):
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
            0 < before.st_size <= MAX_BYTES, "Bounded unaliased nonempty regular input required")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            require(identity(os.fstat(descriptor)) == identity(before), "Input replaced before verified read")
            chunks = []; total = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, MAX_BYTES + 1 - total))
                if not chunk: break
                chunks.append(chunk); total += len(chunk)
                require(total <= MAX_BYTES, "Input grew beyond byte bound")
            require(identity(os.fstat(descriptor)) == identity(before), "Input changed during verified read")
        finally: os.close(descriptor)
        require(path.resolve(strict=True) == path and identity(path.lstat()) == identity(before),
            "Input replaced/aliased after verified read")
    data = b"".join(chunks)
    ref = {"sha256": packet.sha_bytes(data), "bytes": len(data)}
    require(ref["bytes"] == before.st_size, "Input length changed")
    if expected is not None: require(ref == checked_ref(expected), "Original content reference changed")
    return data, ref


def json_input(path, expected=None):
    data, ref = read_verified(path, expected)
    return json.loads(data, object_pairs_hook=packet.unique), ref


def source_contract():
    values = {}
    for name, module in (("extension", __import__(__name__)), ("packet", packet),
            ("derivation", derivation), ("binary_pair", binary), ("signer_structure", signer_structure)):
        path = Path(module.__file__).resolve(strict=True)
        values[name] = {"tool": "android/tools/" + path.name, **read_verified(path)[1]}
    return values


def tree_fence(root):
    root = packet.literal_existing(Path(root), directory=True)
    nodes = [root, *sorted(root.rglob("*"))]
    require(all(p.resolve(strict=True) == p and not p.is_symlink() and
        (p.is_dir() or p.is_file()) for p in nodes), "Aliased/special input tree")
    return {str(p): identity(p.lstat()) for p in nodes}


def authenticate_parent(path, expected_sha256):
    root = packet.literal_existing(Path(path), directory=True)
    require(type(expected_sha256) is str and packet.SHA256.fullmatch(expected_sha256), "External packet receipt pin required")
    before = tree_fence(root)
    receipt, ref = json_input(root / "receipt.json")
    require(ref["sha256"] == expected_sha256, "Parent differs from external packet receipt pin")
    # Unchanged original verifier, exact frozen builder hash and all inventories.
    # Actual member crypto is independently re-run by THIS extension's live gate.
    packet.validate_receipt(root, receipt, expected_sha256, live_tools=False)
    require(tree_fence(root) == before, "Parent changed during original packet verification")
    base_ref = {k:receipt["artifacts"]["conformance"][k] for k in ("sha256", "bytes")}
    first = read_verified(root / "conformance.apk", base_ref)[0]
    second = read_verified(root / packet.CONFORMANCE_UPDATE_DIRECTORY / "candidate.apk",
        receipt["conformance_version_update"]["v2"]["file"])[0]
    pair = binary.apk_pair(first, second)
    require(pair["original"]["version"] == 1 and pair["candidate"]["version"] == 2 and
        pair["original"]["signer"] == pair["candidate"]["signer"] == packet.WONAD_CERT,
        "Exact authenticated ordinary DEV base1/2 required")
    return root, receipt, ref, {1:first, 2:second}, before


def authenticate_tools(path, expected_sha256, image):
    require(type(expected_sha256) is str and packet.SHA256.fullmatch(expected_sha256), "External tools manifest pin required")
    path = packet.literal_existing(Path(path),directory=False)
    names = ("manifest.json","payload-inventory.json","source-packet-receipt.json",
        "source-packet-plan.json","Dockerfile","build-phase1-client-tools.py")
    require(path.name == "manifest.json", "Exact tools manifest bundle name required")
    paths = [path.parent / name for name in names]
    with ExitStack() as stack:
        for p in paths: stack.enter_context(unchanged_file(p))
        before = {str(p):identity(p.lstat()) for p in paths}
        verified = {str(p):read_verified(p) for p in paths}
        manifest_bytes, ref = verified[str(path)]
        require(ref["sha256"] == expected_sha256, "Tools manifest changed")
        evidence = packet.authenticate_tools_image_manifest(Path(path), expected_sha256, image)
        require(packet.canonical(evidence["manifest"]) == packet.canonical(json.loads(manifest_bytes,object_pairs_hook=packet.unique)) and
            {str(p):identity(p.lstat()) for p in paths} == before, "Tools bundle changed during original manifest gate")
        for p in paths: read_verified(p,verified[str(p)][1])
    return evidence, {"image_id": image, "manifest": ref}


def catalogue_bytes(root, parent_bytes, receipt):
    require(receipt["versions"] == [1, 2, 3, 4] and
        all(type(v) is int for v in receipt["versions"]), "Only explicit authenticated1/2/3/4 continuation supported")
    require(set(receipt["members"]) == {"1", "2", "3", "4"}, "Exact continuation member set required")
    result = dict(parent_bytes)
    for version in TARGETS:
        expected = receipt["members"][str(version)]
        require(set(expected) == {"relative", "file"} and expected["relative"] == f"members/v{version}.apk",
            "Foreign continuation member path")
        result[version] = read_verified(root / expected["relative"], expected["file"])[0]
        unsigned = read_verified(root / f"unsigned/v{version}.apk")[0]
        require(unsigned == derivation.unsigned_version_copy(parent_bytes[1], version),
            "Unsigned member is not exact direct-base version-only derivation")
    for version in (1,2):
        require(packet.canonical(receipt["members"][str(version)]) == packet.canonical({"parent_member": version,
            "file": {"sha256":packet.sha_bytes(result[version]),"bytes":len(result[version])}}),
            "Parent member relabelled")
    return result


def pair_proofs(values):
    result = {}
    for before, after in PAIRS:
        pair = binary.apk_pair(values[before], values[after])
        require(pair["original"]["version"] == before and pair["candidate"]["version"] == after and
            pair["original"]["signer"] == pair["candidate"]["signer"] == packet.WONAD_CERT,
            "Continuation version/DEV signer changed")
        result[f"{before}->{after}"] = pair
    return result


def fresh_output(path):
    root = Path(path).absolute()
    require(root.parent.resolve(strict=True) == root.parent and root.parent.is_dir() and
        not root.exists() and not root.is_symlink() and
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,180}", root.name), "Select a fresh literal output child")
    return root


def plan(args):
    parent, receipt, parent_ref, _, fence = authenticate_parent(args.packet, args.expected_packet_receipt_sha256)
    _, tools = authenticate_tools(args.tools_image_manifest, args.tools_image_manifest_sha256, args.tools_image)
    signer = packet.literal_existing(args.signer, directory=True)
    public = packet.literal_existing(args.public_cert, directory=False)
    require(packet.pem_der_hash(public) == packet.pem_der_hash(signer / "certificate.x509.pem") == packet.WONAD_CERT,
        "Only the existing parent DEV certificate is eligible")
    output = fresh_output(args.output)
    require(not output.is_relative_to(parent) and not output.is_relative_to(signer), "Output must not alter packet or signing custody")
    require(tools["image_id"] == receipt["tools"]["image_id"], "Continuation tools differ from parent pinned image")
    return {"kind": KIND, "base_packet": {"path":str(parent),"receipt":parent_ref},
        "targets":list(TARGETS),"tools":tools,"output":str(output),"sources":source_contract(),
        "development_only":True,"new_compilation_claimed":False,"runtime_qualified":False}, fence


def command_row(argv, stdout):
    require(type(stdout) is str and len(stdout.encode()) <= 4 * 1024 * 1024, "Unexpected tool output")
    return {"argv":list(argv),"returncode":0,"stdout":stdout,
        "stdout_sha256":packet.sha_bytes(stdout.encode()),"stdout_bytes":len(stdout.encode())}


@contextmanager
def owned_tools(image):
    tools = packet.Tools(image); primary = None
    try:
        tools.__enter__()
        yield tools
    except BaseException as error:
        primary = error
        raise
    finally:
        if tools.container is not None:
            try: tools.close()
            except BaseException as cleanup:
                if primary is None: raise
                if cleanup is not primary: primary.add_note("Secondary owned-tools cleanup failure: " + repr(cleanup))


def inspect_member(tools, path):
    # Retain the exact real apksigner/aapt/zipalign command outputs, not summaries.
    rows = []
    with packet.SigningSession(tools, path.parent) as session:
        remote = session.put(path, "inspect.apk")
        commands = ((packet.APKSIGNER,"verify","--verbose","--print-certs",remote),
            (packet.AAPT2,"dump","badging",remote),
            (packet.AAPT2,"dump","xmltree","--file","AndroidManifest.xml",remote),
            (packet.ZIPALIGN,"-c","-P","16","4",remote))
        for argv in commands: rows.append(command_row(argv, session.command(*argv)))
        owned_remote = session.remote
    require(tools.exec("test","!","-e",owned_remote) == "", "Inspection temporary directory survives cleanup")
    metadata = {**read_verified(path)[1], **packet.parse_signer(rows[0]["stdout"]),
        **packet.apk_metadata(rows[1]["stdout"],rows[2]["stdout"])}
    return metadata, {"commands":rows,"temporary_directory_removed":True}


def ordinary(metadata, version):
    require(type(metadata["version_code"]) is int and metadata["version_code"] == version and
        metadata["package"] == "org.wonad.desktop" and metadata["version_name"] == "3.0-phase1-conformance" and
        metadata["certificate_der_sha256"] == packet.WONAD_CERT and type(metadata["signers"]) is int and metadata["signers"] == 1 and
        all(metadata[key] is False for key in ("debuggable","test_only","shared_uid","privileged_manifest")) and
        metadata["instrumentation_targets"] == ["org.wonad.desktop"], "Not the exact ordinary conformance identity")


def validate_commands(receipt, values):
    """Reconstruct exact existing-key custody/inspection transcripts."""
    epoch = receipt["tools_epoch"]
    require(type(epoch) is dict and set(epoch) == {"container_id","image_id","label_token"} and
        type(epoch["container_id"]) is str and packet.CONTAINER_ID.fullmatch(epoch["container_id"]) and
        epoch["image_id"] == receipt["tools"]["image_id"] and type(epoch["label_token"]) is str and
        re.fullmatch(r"[0-9a-f]{32}",epoch["label_token"]), "Exact disposable tools epoch required")
    require(set(receipt["signing"]) == {"3","4"} and set(receipt["inspections"]) == set(receipt["metadata"]) == {"1","2","3","4"},
        "Missing/extra member command evidence")
    def rows(value):
        commands = value["commands"]
        require(type(commands) is list and len(commands) == 4, "Exact four-command transcript required")
        for row in commands:
            require(type(row) is dict and set(row) == {"argv","returncode","stdout","stdout_sha256","stdout_bytes"} and
                type(row["returncode"]) is int and row["returncode"] == 0 and type(row["argv"]) is list and
                all(type(a) is str for a in row["argv"]) and type(row["stdout"]) is str and
                type(row["stdout_bytes"]) is int and row["stdout_bytes"] == len(row["stdout"].encode()) <= 4*1024*1024 and
                row["stdout_sha256"] == packet.sha_bytes(row["stdout"].encode()), "Malformed/failed original tool command")
        return commands
    def remote(path, leaf):
        require(type(path) is str and path.endswith("/"+leaf), "Unexpected owned tool member")
        root = path[:-len(leaf)-1]
        require(re.fullmatch(r"/tmp/phase1-client-signing\.[A-Za-z0-9]{8}",root), "Foreign/multiple temporary signing root")
        return root
    for version in TARGETS:
        value = receipt["signing"][str(version)]
        require(set(value) == {"commands","temporary_private_key_removed","existing_development_key_only"} and
            value["temporary_private_key_removed"] is True and value["existing_development_key_only"] is True,
            "Existing-key cleanup/custody not proved")
        commands = rows(value)
        require(len(commands[0]["argv"]) == 10, "Malformed key-conversion command")
        root = remote(commands[0]["argv"][5],"existing.pem")
        expected = [[packet.OPENSSL,"pkcs8","-topk8","-nocrypt","-in",root+"/existing.pem","-outform","DER","-out",root+"/existing.pk8"],
            [packet.ZIPALIGN,"-P","16","-f","4",root+"/unsigned.apk",root+"/aligned.apk"],
            [packet.APKSIGNER,"sign","--key",root+"/existing.pk8","--cert",root+"/existing.x509.pem",
             "--v1-signing-enabled","true","--v2-signing-enabled","true","--v3-signing-enabled","true",
             "--v4-signing-enabled","false","--out",root+"/candidate.apk",root+"/aligned.apk"],
            [packet.ZIPALIGN,"-c","-P","16","4",root+"/candidate.apk"]]
        require([r["argv"] for r in commands] == expected, "Unreviewed/generated-key signing command")
    for version in (1,2,3,4):
        value = receipt["inspections"][str(version)]
        require(set(value) == {"commands","temporary_directory_removed"} and value["temporary_directory_removed"] is True,
            "Inspection cleanup missing")
        commands = rows(value)
        require(len(commands[0]["argv"]) == 5, "Malformed crypto verification command")
        root = remote(commands[0]["argv"][-1],"inspect.apk"); path = root+"/inspect.apk"
        expected = [[packet.APKSIGNER,"verify","--verbose","--print-certs",path],
            [packet.AAPT2,"dump","badging",path],[packet.AAPT2,"dump","xmltree","--file","AndroidManifest.xml",path],
            [packet.ZIPALIGN,"-c","-P","16","4",path]]
        require([r["argv"] for r in commands] == expected, "Unreviewed APK inspection command")
        observed = {"sha256":packet.sha_bytes(values[version]),"bytes":len(values[version]),
            **packet.parse_signer(commands[0]["stdout"]),
            **packet.apk_metadata(commands[1]["stdout"],commands[2]["stdout"])}
        ordinary(observed,version)
        require(packet.canonical(observed) == packet.canonical(receipt["metadata"][str(version)]),
            "Recorded tool output does not derive actual member metadata")


def sign_member(tools, unsigned, candidate, signer):
    rows = []
    with packet.SigningSession(tools, candidate.parent) as session:
        source = session.put(unsigned,"unsigned.apk")
        pem = session.put(signer / "private.pem","existing.pem")
        cert = session.put(signer / "certificate.x509.pem","existing.x509.pem")
        remote = session.remote
        commands = ((packet.OPENSSL,"pkcs8","-topk8","-nocrypt","-in",pem,"-outform","DER","-out",remote+"/existing.pk8"),
            (packet.ZIPALIGN,"-P","16","-f","4",source,remote+"/aligned.apk"),
            (packet.APKSIGNER,"sign","--key",remote+"/existing.pk8","--cert",cert,
             "--v1-signing-enabled","true","--v2-signing-enabled","true","--v3-signing-enabled","true",
             "--v4-signing-enabled","false","--out",remote+"/candidate.apk",remote+"/aligned.apk"),
            (packet.ZIPALIGN,"-c","-P","16","4",remote+"/candidate.apk"))
        for argv in commands: rows.append(command_row(argv,session.command(*argv)))
        session.get("candidate.apk",candidate)
    require(tools.exec("test","!","-e",remote) == "", "Temporary DEV signing materials survive cleanup")
    return {"commands":rows,"temporary_private_key_removed":True,"existing_development_key_only":True}


def prepare(args):
    require(args.allow_development_signing is True, "Explicit DEV signing authorization flag required; planning never signs")
    prepared, before = plan(args)
    parent, parent_receipt, _, values, _ = authenticate_parent(args.packet,args.expected_packet_receipt_sha256)
    output = Path(prepared["output"])
    source_before = source_contract()
    signer = packet.literal_existing(args.signer,directory=True)
    key = signer / "private.pem"
    require(stat.S_ISREG(key.lstat().st_mode) and not key.is_symlink() and key.stat().st_mode & 0o077 == 0,
        "Existing DEV private key custody is not private/literal")
    key_ref = read_verified(key)[1]
    cert_ref = read_verified(signer / "certificate.x509.pem")[1]
    evidence, _ = authenticate_tools(args.tools_image_manifest,args.tools_image_manifest_sha256,args.tools_image)
    output.mkdir(mode=0o700)
    metadata = {}; signing = {}; inspections = {}
    try:
        image_build = packet.stage_tools_image_evidence(output,evidence)
        with owned_tools(args.tools_image) as tools:
            tools_id = {"container_id":tools.container,"image_id":tools.image,"label_token":tools.token}
            for version in TARGETS:
                unsigned = output / f"unsigned/v{version}.apk"
                candidate = output / f"members/v{version}.apk"
                packet.write_new(unsigned,derivation.unsigned_version_copy(values[1],version))
                candidate.parent.mkdir(exist_ok=True)
                signing[str(version)] = sign_member(tools,unsigned,candidate,signer)
                values[version] = read_verified(candidate)[0]
            for version in (1,2,3,4):
                path = (parent / "conformance.apk" if version == 1 else parent / packet.CONFORMANCE_UPDATE_DIRECTORY / "candidate.apk") if version < 3 else output / f"members/v{version}.apk"
                metadata[str(version)], inspections[str(version)] = inspect_member(tools,path)
                ordinary(metadata[str(version)],version)
        # Tools.__exit__ independently verifies disposal; never store private key.
        require(read_verified(key)[1] == key_ref and read_verified(signer / "certificate.x509.pem")[1] == cert_ref,
            "Existing signing custody changed")
        require(tree_fence(parent) == before and source_contract() == source_before, "Parent/source changed during derivation")
        members = {str(v): ({"parent_member":v,"file":{"sha256":packet.sha_bytes(values[v]),"bytes":len(values[v])}}
            if v < 3 else {"relative":f"members/v{v}.apk","file":read_verified(output/f"members/v{v}.apk")[1]}) for v in (1,2,3,4)}
        value = {"schema":1,"kind":KIND,"status":STATUS,"development_only":True,"production_identity":False,
            "runtime_qualified":False,"guests_started":False,"new_compilation_claimed":False,
            "base_packet":prepared["base_packet"],"tools":prepared["tools"],"image_build":image_build,"tools_epoch":tools_id,
            "sources":source_before,"versions":[1,2,3,4],"members":members,"pair_proofs":pair_proofs(values),
            "metadata":metadata,"signing":signing,"inspections":inspections,"tools_container_removed":True,
            "files":packet.inventory(output)}
        validate_commands(value,values)
        packet.write_new(output / "receipt.json",value,canonical_json=True)
        return {"status":STATUS,"receipt":read_verified(output/"receipt.json")[1],"runtime_qualified":False}
    except BaseException as error:
        try:
            packet.write_new(output/"failure.json",{"status":"failed_extension_not_qualified","error":str(error),
                "runtime_qualified":False,"new_compilation_claimed":False},canonical_json=True)
        except BaseException as sealing:
            if sealing is not error: error.add_note("Secondary failure-evidence sealing error: " + repr(sealing))
        raise


def observe_disposed_tools(epoch):
    require(type(epoch["container_id"]) is str and packet.CONTAINER_ID.fullmatch(epoch["container_id"]), "Exact original tools CID required")
    argv = ["docker","container","inspect",epoch["container_id"]]
    began = time.monotonic_ns()
    observed = subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    ended = time.monotonic_ns()
    require(type(observed.returncode) is int and observed.returncode == 1 and observed.stdout.strip() == "[]" and
        re.search(r"No such (?:container|object):?\s+"+re.escape(epoch["container_id"])+r"\b",observed.stderr),
        "Original signing tools container still exists/unobservable")
    return {"argv":argv,"returncode":observed.returncode,"stdout":observed.stdout,"stderr":observed.stderr,
        "stdout_sha256":packet.sha_bytes(observed.stdout.encode()),"stderr_sha256":packet.sha_bytes(observed.stderr.encode()),
        "began_monotonic_ns":began,"ended_monotonic_ns":ended}


def verify(args):
    root = packet.literal_existing(args.extension,directory=True)
    before = tree_fence(root); source_before = source_contract()
    require(type(args.expected_receipt_sha256) is str and packet.SHA256.fullmatch(args.expected_receipt_sha256), "External extension receipt pin required")
    receipt, receipt_ref = json_input(root/"receipt.json")
    require(receipt_ref["sha256"] == args.expected_receipt_sha256, "Extension receipt differs from external pin")
    expected = {"schema","kind","status","development_only","production_identity","runtime_qualified","guests_started",
        "new_compilation_claimed","base_packet","tools","image_build","tools_epoch","sources","versions","members","pair_proofs",
        "metadata","signing","inspections","tools_container_removed","files"}
    require(set(receipt) == expected and type(receipt["schema"]) is int and receipt["schema"] == 1 and receipt["kind"] == KIND and
        receipt["status"] == STATUS and receipt["development_only"] is True and
        all(receipt[key] is False for key in ("production_identity","runtime_qualified","guests_started","new_compilation_claimed")) and
        receipt["tools_container_removed"] is True and packet.canonical(receipt["sources"]) == packet.canonical(source_before), "Extension disclosure/source changed")
    parent, parent_receipt, parent_ref, values, parent_fence = authenticate_parent(args.packet,args.expected_packet_receipt_sha256)
    require(packet.canonical(receipt["base_packet"]) == packet.canonical({"path":str(parent),"receipt":parent_ref}), "Foreign parent packet anchor")
    _, tool_ref = authenticate_tools(args.tools_image_manifest,args.tools_image_manifest_sha256,args.tools_image)
    require(packet.canonical(receipt["tools"]) == packet.canonical(tool_ref), "Extension tools differ from external manifest")
    require(args.tools_image == parent_receipt["tools"]["image_id"] and
        packet.canonical(receipt["image_build"]["manifest"]) == packet.canonical(tool_ref["manifest"]), "Continuation tool image/manifest differs from original packet anchor")
    packet.verify_tools_image_evidence(root,{"image_id":args.tools_image,"image_build":receipt["image_build"]})
    actual = packet.inventory(root); actual.pop("receipt.json")
    require(actual == receipt["files"], "Changed/unsealed extension files")
    expected_files = {f"{role}/v{v}.apk" for role in ("members","unsigned") for v in TARGETS} | {
        "evidence/tools-image/"+name for name in ("manifest.json","payload-inventory.json","source-packet-receipt.json",
            "source-packet-plan.json","Dockerfile","build-phase1-client-tools.py")}
    require(set(actual) == expected_files, "Unexpected/incomplete extension artifact set")
    for ref in receipt["files"].values(): checked_ref(ref)
    values = catalogue_bytes(root,values,receipt)
    require(packet.canonical(pair_proofs(values)) == packet.canonical(receipt["pair_proofs"]), "Base/adjacent binary proof changed")
    validate_commands(receipt,values)
    cleanup_observation = observe_disposed_tools(receipt["tools_epoch"])
    # There is intentionally NO offline/structural-only switch in this gate.
    with owned_tools(args.tools_image) as tools:
        for version in (1,2,3,4):
            path = (parent/"conformance.apk" if version == 1 else parent/packet.CONFORMANCE_UPDATE_DIRECTORY/"candidate.apk") if version < 3 else root/f"members/v{version}.apk"
            observed, _ = inspect_member(tools,path); ordinary(observed,version)
            require(packet.canonical(observed) == packet.canonical(receipt["metadata"][str(version)]), "Actual live cryptographic/APK metadata changed")
    require(tree_fence(root) == before and tree_fence(parent) == parent_fence and source_contract() == source_before,
        "Input/source changed during independent verification")
    return {"kind":KIND,"status":"verified_signed_version_chain_not_runtime_qualified","receipt":receipt_ref,
        "base_packet":receipt["base_packet"],"versions":[1,2,3,4],"members":receipt["members"],"runtime_qualified":False,
        "new_compilation_claimed":False,"original_tools_cleanup_observation":cleanup_observation}


def main():
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest="mode",required=True)
    for mode in ("plan","prepare","verify"):
        command = commands.add_parser(mode)
        command.add_argument("--packet",type=Path,required=True)
        command.add_argument("--expected-packet-receipt-sha256",required=True)
        command.add_argument("--tools-image",required=True)
        command.add_argument("--tools-image-manifest",type=Path,required=True)
        command.add_argument("--tools-image-manifest-sha256",required=True)
        if mode == "verify":
            command.add_argument("--extension",type=Path,required=True)
            command.add_argument("--expected-receipt-sha256",required=True)
        else:
            command.add_argument("--output",type=Path,required=True)
            command.add_argument("--signer",type=Path,required=True)
            command.add_argument("--public-cert",type=Path,required=True)
            if mode == "prepare": command.add_argument("--allow-development-signing",action="store_true")
    args = parser.parse_args()
    result = plan(args)[0] if args.mode == "plan" else prepare(args) if args.mode == "prepare" else verify(args)
    print(json.dumps(result,sort_keys=True))


if __name__ == "__main__": main()
