#!/usr/bin/env python3
"""Exact current TEST-client admission, not an APK updater or campaign gate.

The immutable image/packet remains unchanged when the installed version rises.
The only presently authenticated version-only pair is 1 -> 2. A new durable
forward-only original-journal record is mandatory to admit 2; an old restore
action's temporary version-2 prefix is deliberately not such a record.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import re
import stat
import sys
import time

import conformance_runtime as runtime
import phase1_emulator_client_packet as packet_tool
import phase1_conformance_observations as observations
import phase1_conformance_recents_acceptance as command_semantics
import phase1_conformance_installed_path as installed_paths
from phase1_conformance_common import canonical, file_ref, strict_object

require = runtime.require
APP = runtime.PACKAGE
SERIAL = "emulator-5580"
TRANSITION_KIND = "phase1_policy_free_forward_only_current_client_transition_v1"
TRANSITION_STATUS = "passed_original_forward_only_version_transition_NOT_whole_campaign"
SELECTION_KIND = "phase1_authenticated_current_conformance_member_v1"
MAX_TRANSITION_NS = 180_000_000_000
BASE_BUNDLE = "/opt/wonad/phase1-conformance/conformance.apk"
UPDATE_BUNDLE = "/opt/wonad/phase1-conformance/conformance-update/candidate.apk"
MAX_ORIGINAL_BYTES = 128 * 1024 * 1024


def verified_bytes(path, expected=None):
    """Hash and return ONE nofollow stable read, never a later path read.

    This local boundary does not weaken common.file_ref or allow empty files.
    Metadata is fenced on the opened descriptor AND canonical pathname before
    and after reading; JSON and binary parsers consume these same bytes.
    """
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(),
        "Aliased original current-client bytes")
    def identity(value):
        return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= MAX_ORIGINAL_BYTES,
        "Original current-client file must be unique regular bounded nonempty bytes")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        require(identity(before) == identity(opened), "Original current-client path changed before read")
        def read_opened():
            chunks, size = [], 0
            while size <= before.st_size:
                chunk = os.read(descriptor, min(1024 * 1024, before.st_size + 1 - size))
                if not chunk: break
                chunks.append(chunk); size += len(chunk)
            return b"".join(chunks)
        payload = read_opened()
        # Coarse filesystem timestamp granularity can leave a same-size write
        # in the same tick. A second read through the SAME descriptor must
        # agree, in addition to the stat and authenticated-byte fences.
        os.lseek(descriptor, 0, os.SEEK_SET)
        require(read_opened() == payload, "Original current-client bytes changed during read")
        after = os.fstat(descriptor)
        require(identity(before) == identity(after) == identity(path.lstat()) and
            path.resolve(strict=True) == path and not path.is_symlink() and len(payload) == before.st_size,
            "Original current-client bytes changed during read")
    finally:
        os.close(descriptor)
    ref = {"sha256": hashlib.sha256(payload).hexdigest(), "bytes": len(payload)}
    if expected is not None:
        require(type(expected) is dict and set(expected) <= {"sha256", "bytes"} and "sha256" in expected and
            re.fullmatch(r"[0-9a-f]{64}", str(expected["sha256"])) and
            ("bytes" not in expected or type(expected["bytes"]) is int and expected["bytes"] > 0) and
            all(ref[key] == value for key, value in expected.items()), "Original current-client bytes changed/resealed")
    return payload, ref


def verified_json(path, expected):
    payload, _ = verified_bytes(path, expected)
    return json.loads(payload.decode("utf-8"), object_pairs_hook=strict_object)


def packet_receipt(contract):
    packet = Path(contract["packet"])
    require(packet.is_absolute() and packet.resolve(strict=True) == packet and not packet.is_symlink(),
        "Literal admitted packet required")
    return verified_json(packet / "receipt.json", contract["packet_receipt"])


def source_contract():
    import phase1_conformance_soak_apk_update_acceptance as update
    import phase1_conformance_soak_lock_user_acceptance as uid_parser
    from phase1_conformance_common import strict_object
    return {name: {"path": str(Path(module.__file__).resolve()), **file_ref(Path(module.__file__).resolve())}
        for name, module in {"current_client": sys.modules[__name__], "packet": packet_tool,
            "observations": observations, "update_auditor": update, "uid_parser": uid_parser,
            "reviewed_command_semantics": command_semantics, "installed_path_parser": installed_paths,
            "apk_pair_parser": sys.modules[update.apk_pair.__module__],
            "signer_structure": sys.modules["native_wrong_signer_acceptance"],
            "canary_parser": sys.modules[update.marker_result.__module__],
            "compiled_client_sources": update.lane,
            "common": sys.modules[strict_object.__module__]}.items()}


def catalogue(contract, *, include_successor=False):
    """Reopen the externally admitted original receipt, never an APK summary.

    Signature verification remains the admitted packet/image gate's job. Exact
    signed APK bytes are pinned here; the existing pair parser independently
    reconstructs signer, typed binary version and every non-version payload.
    """
    packet = Path(contract["packet"])
    require(packet.is_absolute() and packet.resolve(strict=True) == packet and not packet.is_symlink(),
        "Literal admitted packet required")
    receipt = packet_receipt(contract); base = receipt["artifacts"]["conformance"]
    require(base["package"] == APP and type(base["version_code"]) is int and base["version_code"] == 1 and
        base["certificate_der_sha256"] == packet_tool.WONAD_CERT and base["signers"] == 1 and
        all(base[key] is False for key in ("debuggable", "shared_uid", "privileged_manifest")),
        "Base client is not the admitted ordinary singleton-signer version1")
    ref = {key: base[key] for key in ("sha256", "bytes")}
    base_bytes, _ = verified_bytes(packet / "conformance.apk", ref)
    result = {1: {"version_code": 1, "artifact": ref, "package": APP,
        "certificate_der_sha256": base["certificate_der_sha256"], "bundle_path": BASE_BUNDLE}}
    if include_successor:
        # Reuse the existing PURE schema, AXML/signer/payload and unsigned-copy
        # validators, but feed them only the already-verified original bytes.
        from native_apk_update_acceptance import apk_pair
        from native_apk_update_smoke import unsigned_version_copy
        import phase1_conformance_clean_boot as lane
        pair = receipt["conformance_version_update"]
        target = packet / packet_tool.CONFORMANCE_UPDATE_DIRECTORY
        preparation = verified_json(target / packet_tool.CONFORMANCE_UPDATE_RECEIPT, pair["receipt"])
        packet_tool.validate_conformance_update_claim(preparation, pair)
        require({entry.name for entry in target.iterdir()} == set(preparation["files"]) | {packet_tool.CONFORMANCE_UPDATE_RECEIPT},
            "Conformance update preparation directory changed")
        originals = {name: verified_bytes(target / name, value)[0] for name, value in preparation["files"].items()}
        original = originals[packet_tool.CONFORMANCE_UPDATE_FILES["original"]]
        candidate = originals[packet_tool.CONFORMANCE_UPDATE_FILES["candidate"]]
        require(original == base_bytes and originals[packet_tool.CONFORMANCE_UPDATE_FILES["unsigned"]] ==
            unsigned_version_copy(original, 2), "Retained unsigned/source version-only derivative changed")
        parsed = apk_pair(original, candidate)
        for role, binary_role in (("v1", "original"), ("v2", "candidate")):
            member, binary = pair[role], parsed[binary_role]
            require(member["file"] == {"sha256": binary["sha256"], "bytes": binary["bytes"]} and
                member["version_code"] == binary["version"] and member["certificate_der_sha256"] == binary["signer"] and
                member["normalized_manifest_sha256"] == binary["manifest"]["normalized_sha256"] and
                member["non_manifest_payload_sha256"] == hashlib.sha256(canonical(binary["payload"])).hexdigest(),
                "Conformance update signed binary inventory changed: " + role)
        # Preserve the original update attachment's compiled client/canary
        # closure without loading separately hashed receipt/freeze bytes.
        freeze_name = "evidence/compile-input/source-freeze.json"
        freeze = verified_json(packet / freeze_name, receipt["files"][freeze_name])
        require(all(freeze["files"].get(relative) == file_ref(lane.ROOT / relative) for relative in lane.CLIENT_FILES),
            "Selected packet predates exact compiled client sources")
        security = receipt["security_compile"]
        require(security["canary_source_sha256"] == packet_tool.UPDATE_CANARY_SHA256 and
            file_ref(lane.ROOT / "android/session-security/src/main/kotlin/org/wonad/desktop/security/UpdateDataInstrumentation.kt")["sha256"] ==
                packet_tool.UPDATE_CANARY_SHA256 and
            receipt["artifacts"]["security"]["certificate_der_sha256"] == base["certificate_der_sha256"],
            "Compiled current canary source/signer changed")
        for name, item in (("security.apk", receipt["artifacts"]["security"]),
            ("security-build-receipt.json", security["receipt"]), ("security-source-freeze.json", security["source_freeze"])):
            verified_bytes(packet / name, {key: item[key] for key in ("sha256", "bytes")})
        require(pair["v1"]["file"] == ref and pair["v1"]["package"] == APP and
            pair["v1"]["certificate_der_sha256"] == base["certificate_der_sha256"], "Foreign pair base/signer")
        member = pair["v2"]
        require(type(member["version_code"]) is int and member["version_code"] == 2 and
            member["package"] == APP and member["certificate_der_sha256"] == base["certificate_der_sha256"],
            "Missing authenticated forward successor member")
        result[2] = {"version_code": 2, "artifact": member["file"], "package": APP,
            "certificate_der_sha256": member["certificate_der_sha256"], "bundle_path": UPDATE_BUNDLE}
    return result


def literal(root, relative):
    require(type(relative) is str and relative and not Path(relative).is_absolute() and
        all(part not in ("", ".", "..") for part in relative.split("/")), "Unsafe current-client evidence path")
    return observations.canonical_path(Path(root) / relative, root)[0]


def checked_trace(trace, identity, *, defer_command_ownership=False):
    require(type(trace) is list and [row.get("sequence") for row in trace] == list(range(len(trace))) and
        all(type(row.get("sequence")) is int for row in trace), "Whole same-guest original journal required")
    previous = 0
    for row in trace:
        kind = row.get("kind")
        if kind == "derived":
            # This is the real recents.Producer.package_identities combine,
            # not an executable guest command and not a fabricated interval.
            require(set(row) == {"kind", "sequence", "inputs", "evidence", "output_sha256"} and
                row["evidence"] == "identity/package-uids.txt" and type(row["inputs"]) is list and
                len(row["inputs"]) == 6 and all(type(at) is int and 0 <= at < row["sequence"] for at in row["inputs"]) and
                len(set(row["inputs"])) == 6 and re.fullmatch(r"[0-9a-f]{64}", str(row["output_sha256"])),
                "Malformed original non-command package UID combine")
            continue
        require(kind in {"command", "background_start", "background_adopt", "background_finish", "owned_test_credential"},
            "Failed/unknown current-client journal event")
        require(type(row.get("started_monotonic_ns")) is int and previous <= row["started_monotonic_ns"],
            "Untyped/reordered current-client journal")
        if kind in {"background_start", "background_adopt"}:
            # Actual initial Producer.start_runtime records the point BEFORE
            # Popen and has neither end nor host_pid. Replacement/adopt points
            # carry a positive observed host_pid and equal start/end clocks.
            require("ended_monotonic_ns" not in row and kind == "background_start" and "host_pid" not in row or
                type(row.get("ended_monotonic_ns")) is int and row["ended_monotonic_ns"] == row["started_monotonic_ns"] and
                type(row.get("host_pid")) is int and row["host_pid"] > 0, "Malformed original instrumentation point event")
            previous = row["started_monotonic_ns"]
        else:
            require(type(row.get("ended_monotonic_ns")) is int and row["started_monotonic_ns"] <= row["ended_monotonic_ns"],
                "Untyped/reordered current-client journal")
            previous = row["ended_monotonic_ns"]
        if kind == "background_finish" and "argv" not in row:
            require(type(row.get("host_pid")) is int and row["host_pid"] > 0 and
                type(row.get("returncode")) is int and type(row.get("id")) is str,
                "Malformed original background completion")
            continue
        require(type(row.get("argv")) is list and all(type(arg) is str for arg in row["argv"]),
            "Missing/invalid original command argv")
        argv = row["argv"]
        if kind in {"background_start", "background_adopt"}:
            require(runtime_start(argv, identity) and row.get("id") == "instrumentation-" + argv[13],
                "Malformed original held runtime instrumentation point")
        if argv[:2] == ["docker", "exec"] and (not defer_command_ownership or kind != "command"):
            require(len(argv) >= 4 and argv[2] == identity["container_id"], "Foreign guest in current-client journal")


def raw(root, trace, identity, relative, suffix, *, binary=False):
    matches = [row for row in trace if row.get("evidence") == relative]
    require(len(matches) == 1, "Missing/duplicate original current-client read")
    row = matches[0]
    require(row["kind"] == "command" and type(row.get("returncode")) is int and row["returncode"] == 0 and
        row["argv"] == ["docker", "exec", identity["container_id"], "adb", "-s", SERIAL, *map(str, suffix)],
        "Unbound/failed current-client command")
    path = literal(root, relative)
    payload, _ = verified_bytes(path, {"sha256": row["output_sha256"]})
    return (payload if binary else payload.decode("utf-8")), row["sequence"]


def observation(root, row, trace, contract, identity, member, uid):
    """Independent actual APK/PM/forward+reverse UID replay; no version trust."""
    from phase1_conformance_soak_lock_user_acceptance import package_uid
    from phase1_conformance_soak_apk_update_acceptance import installed_package
    require(type(uid) is int and 10000 <= uid <= 19999 and
        type(member["version_code"]) is int and member["version_code"] > 0, "Typed original ordinary UID/version required")
    keys = {"uid_before", "reverse_before", "path_before", "dump", "apk", "path_after", "uid_after", "reverse_after"}
    require(set(row) == {"files", "trace_start", "trace_end", "began_monotonic_ns", "ended_monotonic_ns"} and
        set(row["files"]) == keys and all(type(row[key]) is int for key in row if key != "files") and
        0 <= row["trace_start"] < row["trace_end"] <= len(trace) and row["trace_end"] - row["trace_start"] == 8,
        "Complete typed current-client observation required")
    paths, used = row["files"], []
    def read(key, *suffix, binary=False):
        value, sequence = raw(root, trace, identity, paths[key], suffix, binary=binary)
        used.append(sequence); return value
    forward = ("shell", "pm", "list", "packages", "-U", "--user", "0", APP)
    reverse = ("shell", "pm", "list", "packages", "-U", "--user", "0", "--uid", str(uid))
    require(package_uid(read("uid_before", *forward), APP, 0) == uid, "Changed initial client UID")
    require(read("reverse_before", *reverse).splitlines() == [f"package:{APP} uid:{uid}"], "Shared/foreign initial client UID")
    path = read("path_before", "shell", "pm", "path", "--user", "0", APP)
    installed_path = installed_paths.installed_apk_path(path, APP, package_row=True)
    privileges = installed_package(read("dump", "shell", "dumpsys", "package", APP), uid, member["version_code"])
    apk = read("apk", "exec-out", "cat", installed_path, binary=True)
    require({"sha256": hashlib.sha256(apk).hexdigest(), "bytes": len(apk)} == member["artifact"],
        "Installed APK is not exact authenticated current member")
    require(read("path_after", "shell", "pm", "path", "--user", "0", APP) == path, "Installed APK path changed during read")
    require(package_uid(read("uid_after", *forward), APP, 0) == uid and
        read("reverse_after", *reverse).splitlines() == [f"package:{APP} uid:{uid}"], "Recycled/shared final client UID")
    require(used == list(range(row["trace_start"], row["trace_end"])) and
        row["began_monotonic_ns"] <= trace[used[0]]["started_monotonic_ns"] <=
        trace[used[-1]]["ended_monotonic_ns"] <= row["ended_monotonic_ns"], "Current-client read ordering/window changed")
    return {"member": member, "uid": uid, "privileges": privileges, "sequences": used}


def runtime_start(argv, identity):
    prefix = ["docker", "exec", identity["container_id"], "adb", "-s", SERIAL]
    return len(argv) == 24 and argv[:6] == prefix and argv[6:13] == ["shell", "am", "instrument", "-w", "-r", "-e", "run"] and \
        runtime.HEX32.fullmatch(argv[13]) and argv[14:17] == ["-e", "mode", "runtime"] and \
        argv[17:19] == ["-e", "nonce"] and runtime.HEX32.fullmatch(argv[19]) and \
        argv[20:] == ["-e", "phase", "start", runtime.RUNNER]


def reviewed_command(argv, identity, *, credential=False):
    """Closed literal families, NOT an open package-mutation blacklist.

    Exact nonce/PID/user/geometry meanings still require each independent raw
    action auditor. Unknown aliases, container shells and executable paths are
    denied here; these families cannot smuggle a hidden package reset/restore.
    """
    cid = identity["container_id"]
    if argv in (["docker", "container", "inspect", cid], ["docker", "container", "diff", cid]): return True
    screenshot = r"/state/phase1-(?:recents-[0-9a-f]{32}-[0-9a-f]{8}|conformance-update-[0-9a-f]{32}-[0-9a-f]{8})-[123]"
    if len(argv) == 4 and argv[:2] == ["docker", "cp"]:
        source = re.fullmatch(re.escape(cid) + ":" + screenshot + r"/[A-Za-z0-9_.-]+\.png", argv[2])
        return bool(source and Path(argv[3]).is_absolute() and ".." not in Path(argv[3]).parts)
    if argv[:3] == ["docker", "exec", cid] and argv[3:6] != ["adb", "-s", SERIAL]:
        a = argv[3:]
        return a == ["cat", "/opt/wonad/manifest.json"] or \
            a == ["sha256sum", "/opt/wonad/manifest.json", *command_semantics.BUNDLED_APKS.values()] or \
            len(a) == 5 and a[:4] == ["mkdir", "-m", "700", "--"] and bool(re.fullmatch(screenshot, a[4])) or \
            len(a) == 4 and a[:3] == ["rm", "-rf", "--"] and bool(re.fullmatch(screenshot, a[3])) or \
            len(a) == 10 and bool(re.fullmatch(screenshot, a[1])) and a[:1] == ["find"] and \
                a[2:] == ["-maxdepth", "1", "-type", "f", "-name", "*.png", "-printf", "%f\\n"]
    prefix = ["docker", "exec", cid, "adb", "-s", SERIAL]
    if argv[:6] != prefix: return False
    args = argv[6:]
    number = lambda item: bool(re.fullmatch(r"0|[1-9][0-9]*", item))
    positive = lambda item: bool(re.fullmatch(r"[1-9][0-9]*", item))
    package = lambda item: item in {APP, "org.wonad.fixture", "org.wonad.desktop.test", "com.android.phone", "com.android.systemui", "com.android.launcher3"}
    if credential:
        return args in (["shell", "locksettings", "set-pin", "--user", "0", "<owned-test-pin>"],
            ["shell", "locksettings", "clear", "--old", "<owned-test-pin>", "--user", "0"],
            ["shell", "input", "keyboard", "-d", "0", "text", "<owned-test-pin>"])
    if args[:1] == ["exec-out"]:
        if args == ["exec-out", "screencap", "-p"]: return True
        if len(args) != 3 or args[1] != "cat": return False
        if re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml", args[2]): return True
        try: installed_paths.installed_apk_path(args[2]); return True
        except ValueError: return False
    if args[:2] == ["emu", "multidisplay"]:
        return len(args) == 4 and args[2] == "del" and args[3] in ("1", "2", "3") or \
            len(args) == 8 and args[2] == "add" and args[3] in ("1", "2", "3") and all(positive(v) for v in args[4:7]) and args[7] == "132165"
    if args[:4] == ["emu", "screenrecord", "screenshot", "--display"]:
        return len(args) == 6 and args[4] in ("1", "2", "3") and bool(re.fullmatch(screenshot, args[5]))
    if args[:1] != ["shell"]: return False
    a = args[1:]
    if len(a) == 2 and a[0] == "sha256sum":
        if a[1] in set(command_semantics.PRIVILEGED_SYSTEM_PACKAGES.values()) | set(command_semantics.OS_GUEST_PATHS.values()): return True
        try: installed_paths.installed_apk_path(a[1]); return True
        except ValueError: return False
    if a in (["cat", "/proc/sys/kernel/random/boot_id"], ["getenforce"], ["ps", "-A", "-w", "-o", "UID,PID,NAME"],
        ["am", "get-current-user"], list(observations.EVENTS), ["locksettings", "get-disabled", "--user", "0"],
        list(command_semantics.PHONE_HOME_RESOLVE), list(command_semantics.PHONE_TIS_DUMP),
        list(command_semantics.PHONE_OVERVIEW_LOG), list(command_semantics.LOG_CLEAR)): return True
    if len(a) == 2 and a[0] == "getprop": return a[1] in {"ro.build.fingerprint", "sys.boot_completed", "vendor.qemu.vport.modem"}
    if len(a) == 2 and a[0] == "pidof": return a[1] == "system_server" or package(a[1])
    if a[:2] == ["su", "0"]:
        return len(a) == 4 and a[2] == "cat" and bool(re.fullmatch(r"/proc/[1-9][0-9]*/(?:stat|status)", a[3])) or \
            len(a) == 5 and a[2:4] == ["ls", "-1"] and bool(re.fullmatch(r"/proc/[1-9][0-9]*/fd", a[4])) or \
            a[2:] == ["service", "list"] or len(a) == 5 and a[2] == "kill" and a[3] in {"-STOP", "-CONT", "-KILL"} and positive(a[4])
    if a[:1] == ["dumpsys"]:
        if a[1:] in (["activity", "activities"], ["activity", "services"], ["activity", "services", APP], ["activity", "org.wonad.fixture"],
            ["window", "windows"], ["window", "displays"], ["window", "policy"], ["input"], ["display"], ["user"], ["package", APP]): return True
        b = a[2:] if a[1:2] == ["activity"] else []
        if b[:2] == ["--user", "0"]: b = b[2:]
        if b == ["org.wonad.fixture"]: return True
        if b == ["service", "com.android.systemui/.SystemUIService"]: return True
        if b[:2] != ["service", runtime.SERVICE]: return False
        if len(b) == 2: return True
        if len(b) < 6 or b[2] != "runtime-command" or not all(runtime.HEX32.fullmatch(v) for v in b[3:5]): return False
        if b[5] == "expect-revocation": return len(b) == 9 and all(positive(v) for v in b[6:8]) and b[8] in {"3", "4", "5"}
        if b[5] == "expect-broker-death": return len(b) == 8 and all(positive(v) for v in b[6:8])
        return len(b) == 6 and b[5] in set(runtime.PHASES) - {"expect-revocation", "expect-broker-death"}
    if a[:4] == ["cmd", "package", "resolve-activity", "--brief"]:
        return len(a) == 10 and a[4] == "--user" and number(a[5]) and int(a[5]) <= 1000 and \
            a[6:] == ["-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"]
    if a[:1] == ["cmd"] and a[1:2] == ["package"]: a = ["pm", *a[2:]]
    if a[:3] == ["pm", "list", "packages"]:
        b = a[3:]
        if b[:1] == ["-U"]: b = b[1:]
        if len(b) not in (3, 4) or b[:1] != ["--user"] or not number(b[1]): return False
        return len(b) == 3 and package(b[2]) or len(b) == 4 and b[1] == "0" and b[2] == "--uid" and positive(b[3])
    if a[:2] == ["pm", "path"]: return len(a) == 3 and package(a[2]) or len(a) == 5 and a[2:4] == ["--user", "0"] and package(a[4])
    if a[:3] == ["pm", "create-user", "--for-testing"]: return len(a) == 4 and bool(re.fullmatch(r"Wonad-soak-[0-9a-f]{32}", a[3]))
    if a[:2] == ["pm", "remove-user"]: return len(a) == 3 and positive(a[2]) and 10 <= int(a[2]) <= 1000
    if a[:2] in (["am", "start-user"], ["am", "switch-user"]): return len(a) == 4 and a[2] == "-w" and number(a[3]) and int(a[3]) <= 1000
    if a[:2] == ["am", "stop-user"]: return len(a) == 5 and a[2:4] == ["-w", "-f"] and positive(a[4]) and 10 <= int(a[4]) <= 1000
    if a[:2] == ["am", "get-started-user-state"]: return len(a) == 3 and number(a[2]) and int(a[2]) <= 1000
    if a[:2] == ["am", "start"]:
        b = a[2:]
        if b[:1] != ["-W"]: return False
        b = b[1:]
        if b[:2] == ["--user", "0"]: b = b[2:]
        return len(b) == 4 and b[0] == "--display" and number(b[1]) and b[2] == "-n" and bool(re.fullmatch(r"org\.wonad\.fixture/\.[A-Za-z0-9]+Activity", b[3]))
    if a[:2] == ["am", "instrument"]:
        if runtime_start(argv, identity): return True
        return len(a) == 14 and a[:5] == ["am", "instrument", "-w", "-r", "-e"] and a[5] == "mode" and a[6] in {"create", "read"} and \
            a[7:9] == ["-e", "run"] and runtime.HEX32.fullmatch(a[9]) and a[10:12] == ["-e", "nonce"] and \
            runtime.HEX32.fullmatch(a[12]) and a[13] == packet_tool.UPDATE_CANARY_RUNNER
    if a[:1] == ["input"]:
        if len(a) < 6 or a[1] not in {"keyboard", "mouse", "touchscreen"} or a[2] != "-d" or not number(a[3]): return False
        if a[4] == "keyevent": return len(a) == 6 and a[5] in {"KEYCODE_HOME", "KEYCODE_WAKEUP", "KEYCODE_SLEEP", "KEYCODE_LOCK", "KEYCODE_ENTER", "KEYCODE_B", "KEYCODE_BACK", "KEYCODE_APP_SWITCH", "KEYCODE_ALL_APPS"}
        return a[4] == "tap" and len(a) == 7 and all(number(v) for v in a[5:]) or a[4] == "swipe" and len(a) == 10 and all(number(v) for v in a[5:])
    if a[:2] == ["settings", "--user"]: return len(a) == 6 and number(a[2]) and a[3:5] == ["get", "secure"] and a[5] in {"user_setup_complete", "wonad_external_desktop_enabled"}
    if a[:2] == ["locksettings", "set-disabled"]: return len(a) == 5 and a[2:4] == ["--user", "0"] and a[4] in {"true", "false"}
    if a[:2] == ["uiautomator", "dump"] or a[:2] == ["rm", "--"]:
        return len(a) == 3 and bool(re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml", a[2]))
    return False


def target_mutations(trace, identity):
    """Every executable row must be closed-family or an audited exact install."""
    prefix = ["docker", "exec", identity["container_id"], "adb", "-s", SERIAL]
    found = []
    for row in trace:
        argv = row.get("argv", [])
        if "argv" not in row: continue  # Strict non-command/finish schema above.
        require(all("\x00" not in arg and "\n" not in arg and "\r" not in arg for arg in argv),
            "Unadmitted restore/downgrade/reset/update command grammar")
        if argv[:len(prefix)] != prefix:
            if not reviewed_command(argv, identity): found.append(row)
            continue
        args = argv[len(prefix):]
        # Before first observation, enclosing fresh admission may have installed
        # the immutable base once. Later only exact journal-bound -r upgrade is
        # permitted. Reset and shell package aliases are never hidden by a read.
        if args and args[0] in {"install", "uninstall", "install-multiple"}:
            canary = ["install", "-r", "-t", "--user", "0",
                "/opt/wonad/phase1-conformance/update-data-canary/security.apk"]
            if args != canary: found.append(row)
        elif not reviewed_command(argv, identity, credential=row["kind"] == "owned_test_credential"): found.append(row)
    return found


def audit_chain(root, contract, identity, uid, trace, chain, *, defer_command_scan=False):
    """External original refs + complete journal establish a monotone floor.

    No surviving v2 floor is derived from the legacy update/restore report.
    A real callable forward-only update producer remains a separate prerequisite.
    """
    checked_trace(trace, identity, defer_command_ownership=defer_command_scan)
    require(type(chain) in {tuple, list} and len(chain) <= 1, "Authenticated successor chain for versions3+ required; none is present")
    members = catalogue(contract, include_successor=bool(chain)); current = members[1]
    parent = None; admitted_mutations = set(); floor_end = 0
    for ref in chain:
        require(set(ref) == {"path", "sha256", "bytes"}, "External exact forward record reference required")
        path = literal(root, ref["path"])
        value = verified_json(path, {key: ref[key] for key in ("sha256", "bytes")})
        require(set(value) == {"schema", "kind", "status", "identity", "packet_receipt", "sources", "parent", "from_version", "to_version",
            "uid", "before", "after", "install", "seed", "runtime_qualified", "whole_campaign_complete"} and
            type(value["schema"]) is int and value["schema"] == 1 and value["kind"] == TRANSITION_KIND and
            value["status"] == TRANSITION_STATUS and value["identity"] == identity and value["packet_receipt"] == contract["packet_receipt"] and
            value["sources"] == source_contract() and value["parent"] == parent and
            type(value["from_version"]) is int and type(value["to_version"]) is int and
            value["from_version"] == current["version_code"] and value["to_version"] == current["version_code"] + 1 and
            value["to_version"] in members and value["uid"] == uid and type(value["uid"]) is int and
            value["runtime_qualified"] is False and value["whole_campaign_complete"] is False,
            "Not a new authenticated forward-only current-version record")
        before = observation(root, value["before"], trace, contract, identity, current, uid)
        after = observation(root, value["after"], trace, contract, identity, members[value["to_version"]], uid)
        require({key: data for key, data in before["privileges"].items() if key != "version_code"} ==
            {key: data for key, data in after["privileges"].items() if key != "version_code"}, "Forward transition changed privileges")
        installed, sequence = raw(root, trace, identity, value["install"], ("install", "-r", "--user", "0", UPDATE_BUNDLE))
        require(installed.strip().splitlines()[-1:] == ["Success"] and
            floor_end <= value["before"]["trace_start"] < value["before"]["trace_end"] <= sequence < value["after"]["trace_start"] and
            0 < value["after"]["ended_monotonic_ns"] - value["before"]["began_monotonic_ns"] <= MAX_TRANSITION_NS,
            "Forward update lacks original successful exact install-r ordering")
        from phase1_conformance_soak_apk_update_acceptance import marker_result, canary_argv
        seed = value["seed"]
        require(set(seed) == {"run", "nonce", "create", "read", "canary_before", "canary_after"} and
            runtime.HEX32.fullmatch(seed["run"]) and runtime.HEX32.fullmatch(seed["nonce"]), "Original data-continuity seed required")
        for mode, version in (("create", 1), ("read", 2)):
            raw_marker, at = raw(root, trace, identity, seed[mode], canary_argv([], seed, mode))
            marker_result(raw_marker, mode, seed["run"], seed["nonce"], uid, version, identity["fingerprint"])
            require(at < value["before"]["trace_start"] if mode == "create" else sequence < at < value["after"]["trace_start"],
                "Private data proof escaped original update interval")
            canary = seed["canary_before" if mode == "create" else "canary_after"]
            require(set(canary) == {"path", "apk"}, "Original installed canary APK proof required")
            source = packet_receipt(contract)["artifacts"]["security"]
            located, _ = raw(root, trace, identity, canary["path"], ("shell", "pm", "path", "--user", "0", source["package"]))
            installed_path = installed_paths.installed_apk_path(located, source["package"], package_row=True)
            apk, _ = raw(root, trace, identity, canary["apk"], ("exec-out", "cat", installed_path), binary=True)
            require({"sha256": hashlib.sha256(apk).hexdigest(), "bytes": len(apk)} ==
                {key: source[key] for key in ("sha256", "bytes")}, "Foreign installed data canary APK")
        admitted_mutations.add(sequence); floor_end = value["after"]["trace_end"]
        current = members[value["to_version"]]; parent = ref
    if not defer_command_scan:
        for mutation in target_mutations(trace, identity):
            if mutation["sequence"] in admitted_mutations: continue
            raise ValueError("Unadmitted restore/downgrade/reset/update in whole same-guest journal")
    return {"kind": SELECTION_KIND, "identity": identity, "packet_receipt": contract["packet_receipt"],
        "uid": uid, "member": current, "chain": list(chain)}


class CurrentClient:
    def __init__(self, test, contract):
        self.test, self.contract = test, copy.deepcopy(contract)
        self.identity = copy.deepcopy(test.sampler_identity); self.uid = test.uids[APP]; self.chain = []
        require(type(self.uid) is int and 10000 <= self.uid <= 19999, "Original admitted client UID required")
        catalogue(contract)

    def advance_forward(self, record_path, expected_ref):
        require(self.test.sampler_identity == self.identity, "Current client owner changed")
        relative = Path(record_path).relative_to(self.test.output).as_posix()
        proposed = [*self.chain, {"path": relative, **expected_ref}]
        audit_chain(self.test.output, self.contract, self.identity, self.uid, self.test.trace, proposed)
        self.chain = proposed

    def selection(self):
        require(self.test.sampler_identity == self.identity and self.test.uids[APP] == self.uid, "Current client owner/UID reset")
        return audit_chain(self.test.output, self.contract, self.identity, self.uid, self.test.trace, self.chain)

    def observe(self, actor, label):
        selection = self.selection(); member = selection["member"]
        row = read_member(actor, label, member, self.uid)
        require(self.selection() == selection, "Current client admission changed during original observation")
        actor.action["client_observations"].append(row)
        return selection


def current_client_for(test, contract, selected=None):
    original = getattr(test, "current_client_admission", None)
    if original is None:
        require(selected is None, "Cannot replace original current-client floor with a caller assertion")
        original = CurrentClient(test, contract); test.current_client_admission = original
    require(isinstance(original, CurrentClient) and original.test is test and original.contract == contract and
        (selected is None or selected is original), "Never reset/relabel the held guest's current-client floor")
    original.selection()
    return original


def read_member(actor, label, member, uid):
    """Read-only transition seam: observes bytes, NEVER advances authority.

    A future forward-only writer may use this for its before/after raw rows;
    it still needs original install/canary/whole-journal proof and advance_forward.
    """
    require(type(label) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,47}", label), "Literal fresh client label required")
    test = actor.test; prefix = actor.prefix + "/current-client/" + label
    files = {key: prefix + (".apk" if key == "apk" else "-" + key + ".txt") for key in
        ("uid_before", "reverse_before", "path_before", "dump", "apk", "path_after", "uid_after", "reverse_after")}
    require(all(not (test.output / path).exists() and not (test.output / path).is_symlink() for path in files.values()),
        "Never overwrite existing original client observations")
    require(test.output.resolve(strict=True) == test.output and not test.output.is_symlink(), "Literal original observer root required")
    for relative in files.values():
        parent = test.output
        for part in Path(relative).parts[:-1]:
            parent /= part
            require(not parent.is_symlink() and (not parent.exists() or parent.is_dir() and parent.resolve(strict=True) == parent),
                "Unexpected observer parent/symlink; preserve it")
    began, start = time.monotonic_ns(), len(test.trace)
    forward = ("pm", "list", "packages", "-U", "--user", "0", APP)
    reverse = ("pm", "list", "packages", "-U", "--user", "0", "--uid", str(uid))
    actor.raw_read(files["uid_before"], *forward); actor.raw_read(files["reverse_before"], *reverse)
    path = actor.raw_read(files["path_before"], "pm", "path", "--user", "0", APP)
    installed_path = installed_paths.installed_apk_path(path, APP, package_row=True)
    actor.raw_read(files["dump"], "dumpsys", "package", APP)
    test.adb("exec-out", "cat", installed_path, evidence=files["apk"], binary=True)
    actor.raw_read(files["path_after"], "pm", "path", "--user", "0", APP)
    actor.raw_read(files["uid_after"], *forward); actor.raw_read(files["reverse_after"], *reverse)
    row = {"files": files, "trace_start": start, "trace_end": len(test.trace),
        "began_monotonic_ns": began, "ended_monotonic_ns": time.monotonic_ns()}
    observation(test.output, row, test.trace, actor.contract, test.sampler_identity, member, uid)
    return row


def begin_action(actor):
    actor.action.update(current_client=actor.current_client.selection(), client_observations=[])


def finish_journal(actor):
    """Durable complete original runtime journal, including failed attempts."""
    from phase1_conformance_clean_boot import fresh
    relative = actor.prefix + "/current-client-journal.json"
    fresh.write_new_durable(actor.test.output / relative, actor.test.trace)
    actor.action["current_client_journal"] = {"path": relative, **file_ref(actor.test.output / relative)}


def audit_action(root, action, trace, contract, identity, *, client_chain=None, client_uid=None, defer_command_scan=False):
    """External admitted chain is mandatory: never adopt the report's floor."""
    require(client_chain is None or type(client_chain) in {tuple, list}, "External original client chain required")
    ref = action["current_client_journal"]
    require(set(ref) == {"path", "sha256", "bytes"} and type(ref["bytes"]) is int and ref["bytes"] > 0,
        "Complete original whole-client journal reference required")
    prefix = f"soak-actions/{action['ordinal']:06d}-{action['scenario']}-{action['nonce']}"
    require(ref["path"] == prefix + "/current-client-journal.json", "Aliased current-client original journal path")
    journal = literal(root, ref["path"])
    whole = verified_json(journal, {key: ref[key] for key in ("sha256", "bytes")})
    require(whole[action["trace_start"]:action["trace_end"]] == trace and len(whole) == action["trace_end"],
        "Lost/relabelled original whole same-guest journal")
    uid = action["uids"][APP]
    require((not client_chain or type(client_uid) is int) and
        (client_uid is None or type(client_uid) is int and 10000 <= client_uid <= 19999 and uid == client_uid),
        "External original admitted UID required; foreign/current UID summary rejected")
    # Parent semantic auditors first need the independently verified eight-read
    # exclusions. They MAY defer only this scan until their original specific
    # command parser completes, then MUST call this function again at defaults.
    # No parent verdict/producer selection can use the deferred intermediate
    # proof alone. This preserves original hostile command predicates/errors.
    selected = audit_chain(root, contract, identity, uid, whole, () if client_chain is None else client_chain,
        defer_command_scan=defer_command_scan)
    require(action["current_client"] == selected, "Self-reported/relabelled current client version/floor")
    rows = action["client_observations"]
    require(len(rows) == 2 and rows[0]["trace_start"] >= action["trace_start"] and
        rows[0]["trace_end"] <= action["captures"][0]["trace_start"] and
        rows[1]["trace_start"] >= action["captures"][-1]["trace_end"] and rows[1]["trace_end"] <= action["trace_end"],
        "Current client observations must bracket all original action captures")
    for row, label in zip(rows, ("before", "after")):
        require(all(relative == prefix + "/current-client/" + label +
            (".apk" if key == "apk" else "-" + key + ".txt") for key, relative in row["files"].items()),
            "Aliased/replayed original client observation paths")
    proofs = [observation(root, row, whole, contract, identity, selected["member"], uid) for row in rows]
    require(proofs[0]["privileges"] == proofs[1]["privileges"], "Current client privilege/UID changed across scenario")
    return {"selection": selected, "sequences": set(sequence for proof in proofs for sequence in proof["sequences"])}
