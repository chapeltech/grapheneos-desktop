"""Adversarial tests for the independent fresh-Recents guest auditor."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tools"))

import test_phase1_fresh_conformance as base
import phase1_conformance_recents_guest_acceptance as acceptance


class FreshRecentsGuestAcceptanceTests(base.Fixture):
    container = "a" * 64
    image = "sha256:" + "b" * 64
    boot = "12345678-1234-1234-1234-123456789abc"
    container_run = "c" * 32
    recents_run = "d" * 32
    conformance_run = "e" * 32

    def row(self, argv, tick, output="", *, returncode=0, evidence=None, output_sha256=None):
        value = {"argv": argv, "returncode": returncode,
                 "started_monotonic_ns": tick, "ended_monotonic_ns": tick + 1}
        if evidence is None:
            value["output"] = output
        else:
            value.update(evidence=evidence, output_sha256=output_sha256)
        return value

    def fixture(self):
        ordinal = getattr(self, "_fixture_ordinal", 0) + 1
        self._fixture_ordinal = ordinal
        stage, manifest = self.stage(f"recents-candidate-stage-{ordinal}")
        root = self.root / f"fresh-recents-{ordinal}"
        guest, child = root / "guest", root / "recents"
        guest.mkdir(parents=True); child.mkdir()
        state_dir = guest / "emulator-state"
        state_dir.mkdir(mode=0o700)
        (state_dir / "tmp").mkdir(mode=0o700)
        (guest / "image-manifest.json").write_bytes(base.common.canonical(manifest))
        (guest / "product-candidate-manifest.json").write_bytes(
            (stage / "product-candidate-manifest.json").read_bytes())
        (guest / "packet-receipt.json").write_bytes((self.packet / "receipt.json").read_bytes())
        hierarchy = ('<?xml version="1.0"?><hierarchy><node package="com.android.systemui" '
                     'text="Enable Wonad desktop" enabled="true" clickable="true" '
                     'bounds="[100,100][200,200]" /></hierarchy>')
        (guest / "consent-hierarchy.xml").write_text(hierarchy)
        (guest / acceptance.fresh.PHONE_HOME_ACTIVITIES).write_text(
            base.phone_home_activities())
        (guest / acceptance.fresh.PHONE_HOME_WINDOWS).write_text(
            base.phone_home_windows())
        (guest / "protected-events.txt").write_text("--------- beginning of events\n")
        processes = {"system_server": {"pid": 101, "start_ticks": 1001},
                     "com.android.systemui": {"pid": 202, "start_ticks": 1002},
                     "com.android.launcher3": {"pid": 303, "start_ticks": 1003},
                     "com.android.phone": {"pid": 404, "start_ticks": 1004}}
        installed = {
            acceptance.FIXTURE: {"path": "/data/app/fixture/base.apk",
                                 "sha256": self.artifacts["fixture"]["sha256"]},
            acceptance.APP: {"path": "/data/app/conformance/base.apk",
                             "sha256": self.artifacts["conformance"]["sha256"]},
        }
        common_state = {"boot_id": self.boot, "fingerprint": base.FINGERPRINT,
            "abi": "x86_64", "enforcing": "Enforcing", "current_user": "0",
            "consent": "1", "protected_processes": processes, "display_id": None,
            "installed": installed, "os_artifacts": self.os_artifacts}
        before = {**common_state,
            "packages": {acceptance.APP: None, acceptance.FIXTURE: None, acceptance.FAULT: None},
            "consent_point": [150, 150]}
        after = {**common_state,
            "packages": {acceptance.APP: installed[acceptance.APP]["path"],
                         acceptance.FIXTURE: installed[acceptance.FIXTURE]["path"],
                         acceptance.FAULT: None}, "consent_point": None}
        (guest / "before.json").write_bytes(base.common.canonical(before))
        (guest / "after.json").write_bytes(base.common.canonical(after))

        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        rows, tick = [], 1
        def add(argv, output="", **kwargs):
            nonlocal tick
            rows.append(self.row(argv, tick, output, **kwargs)); tick += 2
        def process(name):
            epoch = processes[name]; pid = epoch["pid"]
            fields = ["1"] * 19; fields[18] = str(epoch["start_ticks"])
            add(prefix + ["shell", "pidof", name], str(pid) + "\n")
            add(prefix + ["shell", "su", "0", "cat", f"/proc/{pid}/stat"],
                f"{pid} ({name}) S " + " ".join(fields) + "\n")
        def inspect(running):
            add(["docker", "container", "inspect", self.container], json.dumps([{
                "Id": self.container, "Image": self.image,
                "Config": {"Labels": {acceptance.LABEL: self.container_run},
                           "User": "1000:1000"},
                "Mounts": [{"Type": "bind", "Destination": "/state",
                            "Source": str(guest / "emulator-state"), "Mode": "rw,Z",
                            "RW": True, "Propagation": "rprivate"}],
                "HostConfig": {"Binds": [str(guest / "emulator-state") + ":/state:rw,Z"],
                               "NetworkMode": "none", "Privileged": False,
                               "PortBindings": {}, "PublishAllPorts": False,
                               "CapAdd": None, "CapDrop": ["ALL"],
                               "SecurityOpt": ["no-new-privileges=true"],
                               "PidMode": "", "IpcMode": "private", "UTSMode": "",
                               "UsernsMode": "", "CgroupnsMode": "private",
                               "VolumesFrom": None, "AutoRemove": False,
                               "ReadonlyRootfs": False,
                               "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                               "GroupAdd": ["103"],
                               "Devices": [{"PathOnHost": "/dev/kvm",
                                            "PathInContainer": "/dev/kvm",
                                            "CgroupPermissions": "rwm"}],
                               "DeviceRequests": None, "DeviceCgroupRules": None,
                               "PidsLimit": 1024, "Memory": 8 * 1024 ** 3,
                               "MemorySwap": 16 * 1024 ** 3, "MemoryReservation": 0,
                               "OomKillDisable": False,
                               "NanoCpus": 12_000_000_000,
                               "ShmSize": 512 * 1024 ** 2,
                               "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=2g"},
                               "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0},
                                           {"Name": "nofile", "Hard": 65536, "Soft": 65536}]},
                "State": {"Running": running}}]))
        def identity_bundle():
            add(prefix + ["shell", "cat", "/proc/sys/kernel/random/boot_id"], self.boot + "\n")
            add(prefix + ["shell", "getprop", "ro.build.fingerprint"], base.FINGERPRINT + "\n")
            add(prefix + ["shell", "getprop", "ro.product.cpu.abi"], "x86_64\n")
            add(prefix + ["shell", "getenforce"], "Enforcing\n")
            add(prefix + ["shell", "am", "get-current-user"], "0\n")
            add(prefix + ["shell", "settings", "--user", "0", "get", "secure",
                          "wonad_external_desktop_enabled"], "1\n")
            for role, path in acceptance.fresh.OS_GUEST_PATHS.items():
                add(prefix + ["shell", "sha256sum", path], self.os_artifacts[role] + "  " + path + "\n")

        add(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs",
             "/tmp:rw,nosuid,size=64m", self.image, "verify"],
            "Verifying fresh-guest Phase-1 conformance candidate…\n" +
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n")
        product_manifest = base.common.load(guest / "product-candidate-manifest.json")
        add(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint",
             "cat", self.image, "/opt/wonad/product-candidate-manifest.json"],
            json.dumps(product_manifest, sort_keys=True, separators=(",", ":")) + "\n")
        def identity(path):
            value = os.lstat(path)
            return {"path": str(path), "dev": value.st_dev, "ino": value.st_ino,
                    "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid,
                    "gid": value.st_gid}
        authority = {
            "runner": {"path": "android/tools/run_phase1_conformance_recents_guest.py",
                       **base.common.file_ref(
                           acceptance.ROOT / "android/tools/run_phase1_conformance_recents_guest.py")},
            "guest_common": {"path": "android/tools/phase1_conformance_guest.py",
                             **base.common.file_ref(
                                 acceptance.ROOT / "android/tools/phase1_conformance_guest.py")},
        }
        prelaunch = {"schema": 1, "kind": acceptance.fresh.PRELAUNCH_USERDATA_KIND,
            "timeline": {"create_started_monotonic_ns": 5,
                         "state_created_monotonic_ns": 6,
                         "tmp_created_monotonic_ns": 7,
                         "inventory_observed_monotonic_ns": 8},
            "state": identity(state_dir), "tmp": identity(state_dir / "tmp"),
            "inventory": [{"path": "tmp", "kind": "directory", "children": []}],
            "authority": authority}
        prelaunch_path = guest / acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE
        prelaunch_path.write_bytes(base.common.canonical(prelaunch))
        prelaunch_ref = base.common.file_ref(prelaunch_path)
        rows.append({"kind": "local_evidence", "name": acceptance.fresh.PRELAUNCH_LOCAL_EVENT,
                     "started_monotonic_ns": 9, "ended_monotonic_ns": 10,
                     "evidence": acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE,
                     "output_sha256": prelaunch_ref["sha256"],
                     "bytes": prelaunch_ref["bytes"]})
        tick = 11
        add(["docker", "run", "-d", "--name",
             "wonad-phase1-conformance-" + self.container_run[:12],
             "--label", acceptance.LABEL + "=" + self.container_run, "--network", "none",
             "--device", "/dev/kvm", "--group-add", "103", "--user", "1000:1000",
             "--cap-drop=ALL", "--security-opt", "no-new-privileges=true", "--pids-limit", "1024",
             "--memory", "8g", "--cpus", "12", "--shm-size", "512m",
             "--ulimit", "nofile=65536:65536", "--ulimit", "core=0:0",
             "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
             "--volume", str(guest / "emulator-state") + ":/state:rw,Z",
             "--env", "HOME=/state", "--env", "TMPDIR=/state/tmp",
             "--env", "WONAD_VIEWER_TRANSPORT=vnc", "--entrypoint", "python3",
             self.image, "/opt/wonad/session.py"], self.container + "\n")
        inspect(True); inspect(True)
        add(prefix + ["shell", "getprop", "sys.boot_completed"], "1\n")
        for package in (acceptance.APP, acceptance.FIXTURE, acceptance.FAULT):
            add(prefix + ["shell", "pm", "path", package], "", returncode=1)
        add(prefix + ["shell", "dumpsys", "activity", "service",
                      "com.android.systemui/.SystemUIService"],
            " KeyguardStateController:\n mShowing: false\n mSecure: false\n mCanDismissLockScreen: true\n")
        add(prefix + ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_WAKEUP"])
        add(prefix + ["shell", "am", "get-current-user"], "0\n")
        add(prefix + ["shell", "pm", "list", "users"], "Users:\nUserInfo{0:Owner:13} running\n")
        for name in sorted(acceptance.PROTECTED): process(name)
        for package, role in ((acceptance.FIXTURE, "fixture"), (acceptance.APP, "conformance")):
            add(prefix + ["shell", "pm", "path", package], "", returncode=1)
            add(prefix + ["install", "--user", "0",
                          "/opt/wonad/phase1-conformance/" + role + ".apk"], "Success\n")
            path = installed[package]["path"]
            add(prefix + ["shell", "pm", "path", package], "package:" + path + "\n")
            add(prefix + ["shell", "sha256sum", path], installed[package]["sha256"] + "  " + path + "\n")
        add(prefix + ["shell", "pm", "path", acceptance.FAULT], "", returncode=1)
        add(prefix + ["shell", "settings", "--user", "0", "get", "secure",
                      "wonad_external_desktop_enabled"], "null\n")
        add(prefix + ["shell", "am", "start", "-W", "--display", "0", "-n",
                      acceptance.fresh.SETTINGS], "Status: ok\n")
        remote = "/data/local/tmp/wonad-phase1-consent-" + self.container_run + ".xml"
        add(prefix + ["shell", "uiautomator", "dump", "--compressed", remote], "dumped\n")
        add(prefix + ["exec-out", "cat", remote], hierarchy + "\n")
        add(prefix + ["shell", "rm", "--", remote])
        add(prefix + ["shell", "input", "touchscreen", "-d", "0", "tap", "150", "150"])
        add(prefix + ["shell", "settings", "--user", "0", "get", "secure",
                      "wonad_external_desktop_enabled"], "1\n")
        add(prefix + ["shell", "cmd", "package", "resolve-activity", "--components",
                      "--user", "0", "-a", acceptance.fresh.HOME_ACTION, "-c",
                      acceptance.fresh.HOME_CATEGORY], base.HOME_COMPONENT + "\n")
        add(prefix + ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
        add(prefix + ["shell", "dumpsys", "activity", "activities"],
            (guest / acceptance.fresh.PHONE_HOME_ACTIVITIES).read_text())
        add(prefix + ["shell", "dumpsys", "window", "windows"],
            (guest / acceptance.fresh.PHONE_HOME_WINDOWS).read_text())
        identity_bundle()
        setup_end = rows[-1]["ended_monotonic_ns"]
        tick = 2001
        terminal_start = tick
        for package in (acceptance.APP, acceptance.FIXTURE, acceptance.FAULT):
            value = "" if package == acceptance.FAULT else "package:" + installed[package]["path"] + "\n"
            add(prefix + ["shell", "pm", "path", package], value,
                returncode=1 if package == acceptance.FAULT else 0)
        for package in (acceptance.APP, acceptance.FIXTURE):
            path = installed[package]["path"]
            add(prefix + ["shell", "sha256sum", path], installed[package]["sha256"] + "  " + path + "\n")
        for name in sorted(acceptance.PROTECTED): process(name)
        identity_bundle()
        add(prefix + ["shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
                      "am_anr:I", "am_crash:I", "*:S"], evidence="protected-events.txt",
            output_sha256=base.common.sha256(guest / "protected-events.txt"))
        inspect(True)
        add(["docker", "stop", "-t", "30", self.container], self.container + "\n")
        inspect(False)
        (guest / "commands.json").write_bytes(base.common.canonical(rows))

        child_trace = [
            {**self.row(["docker", "container", "inspect", self.container],
                        setup_end + 10, "[]"), "sequence": 0, "kind": "command"},
            {"sequence": 1, "kind": "background_start", "id": "instrumentation-1",
             "argv": ["instrument"], "started_monotonic_ns": setup_end + 20},
            {"sequence": 2, "kind": "derived", "inputs": [0, 0, 0, 0],
             "evidence": "identity.txt", "output_sha256": "0" * 64},
            {"sequence": 3, "kind": "background_finish", "id": "instrumentation-1",
             "returncode": 0, "ended_monotonic_ns": setup_end + 30,
             "evidence": "instrument.txt", "output_sha256": "1" * 64},
            {**self.row(["docker", "container", "inspect", self.container],
                        setup_end + 40, "[]"), "sequence": 4, "kind": "command"},
        ]
        self.assertLess(child_trace[-1]["ended_monotonic_ns"], terminal_start)
        (child / "commands.json").write_bytes(base.common.canonical(child_trace))
        child_report = {"container_id": self.container, "image_id": self.image,
                        "boot_id": self.boot, "fingerprint": base.FINGERPRINT,
                        "run": self.recents_run, "conformance_run": self.conformance_run}
        (child / "report.json").write_bytes(base.common.canonical(child_report))
        child_ref = base.common.file_ref(child / "report.json")
        child_audit = {
            "status": "accepted_conformance_recents_not_runtime_or_hardware_qualification",
            "run": self.recents_run, "conformance_run": self.conformance_run,
            "image_id": self.image, "boot_id": self.boot,
            "report_sha256": child_ref["sha256"],
        }
        evidence = {path.name: base.common.file_ref(path) for path in guest.iterdir() if path.is_file()}
        report = {"schema": 1, "kind": acceptance.KIND, "status": acceptance.STATUS,
            "image_id": self.image, "container_id": self.container, "boot_id": self.boot,
            "fingerprint": base.FINGERPRINT, "packet_receipt_sha256": self.receipt_sha,
            "recents_report": {"path": "recents/report.json", **child_ref},
            "recents_audit": child_audit, "product_images": manifest["product_images"],
            "os_artifacts": manifest["os_artifacts"], "artifacts": manifest["artifacts"],
            "guest_setup_evidence": evidence,
            "prelaunch_state": {**prelaunch, "evidence": {
                "path": "guest/" + acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE,
                **prelaunch_ref}}, "authority": authority,
            "ordinary_ui_consent": True, "settings_state_seeded": False,
            "fault_apk_installed": False, "container_stopped": True,
            "userdata_retained_path": str(guest / "emulator-state"),
            "runtime_qualified": False, "qualification_claimed": False}
        (root / "report.json").write_bytes(base.common.canonical(report))
        return root, report, child_audit

    def audit(self, root, child_audit):
        with patch.object(acceptance.packet_tool, "validate_receipt", return_value=None), \
             patch.object(acceptance.recents_acceptance, "audit_report", return_value=child_audit):
            return acceptance.audit_report(root / "report.json", self.product, self.packet,
                                           self.receipt_sha, external_checks=False)

    def reseal_guest(self, root, name, value=None):
        path = root / "guest" / name
        if value is not None:
            path.write_bytes(base.common.canonical(value))
        report = base.common.load(root / "report.json")
        report["guest_setup_evidence"][name] = base.common.file_ref(path)
        (root / "report.json").write_bytes(base.common.canonical(report))

    def reseal_prelaunch(self, root, raw, *, canonical=True):
        path = root / "guest" / acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE
        path.write_bytes(base.common.canonical(raw) if canonical else
                         (json.dumps(raw, indent=2, sort_keys=True) + "\n").encode())
        reference = base.common.file_ref(path)
        trace = base.common.load(root / "guest/commands.json")
        local = next(row for row in trace if row.get("kind") == "local_evidence")
        local["output_sha256"] = reference["sha256"]
        local["bytes"] = reference["bytes"]
        (root / "guest/commands.json").write_bytes(base.common.canonical(trace))
        report = base.common.load(root / "report.json")
        report["prelaunch_state"] = {**raw, "evidence": {
            "path": "guest/" + acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE,
            **reference}}
        report["authority"] = raw["authority"]
        report["guest_setup_evidence"][acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE] = reference
        report["guest_setup_evidence"]["commands.json"] = base.common.file_ref(
            root / "guest/commands.json")
        (root / "report.json").write_bytes(base.common.canonical(report))

    def retime_around_child(self, root, trace, *, sync_prelaunch=True):
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        wanted = [["shell", "pm", "path", package]
                  for package in (acceptance.APP, acceptance.FIXTURE, acceptance.FAULT)]
        starts = [index for index in range(len(trace) - 2)
                  if all(trace[index + offset].get("argv", [])[:len(prefix)] == prefix
                         for offset in range(3)) and
                  [trace[index + offset]["argv"][len(prefix):] for offset in range(3)] == wanted]
        terminal = starts[-1]
        tick = 3
        for index, row in enumerate(trace):
            if index == terminal:
                tick += 1000
            row["started_monotonic_ns"] = tick
            duration = (row.get("timeout_seconds", 0) * 1_000_000_000
                        if row.get("timed_out") is True else 1)
            row["ended_monotonic_ns"] = tick + duration
            tick = row["ended_monotonic_ns"] + 2
        if sync_prelaunch:
            manifest_index = next(index for index, row in enumerate(trace)
                                  if row.get("argv", [])[-2:] ==
                                  [self.image, "/opt/wonad/product-candidate-manifest.json"])
            local = next(row for row in trace if row.get("kind") == "local_evidence")
            raw_path = root / "guest" / acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE
            raw = base.common.load(raw_path)
            raw["timeline"] = {
                "create_started_monotonic_ns": trace[manifest_index]["ended_monotonic_ns"],
                "state_created_monotonic_ns": local["started_monotonic_ns"] - 1,
                "tmp_created_monotonic_ns": local["started_monotonic_ns"],
                "inventory_observed_monotonic_ns": local["started_monotonic_ns"],
            }
            raw_path.write_bytes(base.common.canonical(raw))
            raw_ref = base.common.file_ref(raw_path)
            local["output_sha256"] = raw_ref["sha256"]
            local["bytes"] = raw_ref["bytes"]
            report = base.common.load(root / "report.json")
            report["prelaunch_state"] = {**raw, "evidence": {
                "path": "guest/" + acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE,
                **raw_ref}}
            report["guest_setup_evidence"][acceptance.fresh.PRELAUNCH_USERDATA_EVIDENCE] = raw_ref
            (root / "report.json").write_bytes(base.common.canonical(report))
        low, high = trace[terminal - 1]["ended_monotonic_ns"], trace[terminal]["started_monotonic_ns"]
        child = base.common.load(root / "recents/commands.json")
        cursor = low + 10
        for row in child:
            if row["kind"] == "command":
                row["started_monotonic_ns"] = cursor
                row["ended_monotonic_ns"] = cursor + 1
                cursor += 10
            elif row["kind"] == "background_start":
                row["started_monotonic_ns"] = cursor; cursor += 10
            elif row["kind"] == "background_finish":
                row["ended_monotonic_ns"] = cursor; cursor += 10
        self.assertLess(cursor, high)
        (root / "recents/commands.json").write_bytes(base.common.canonical(child))
        self.reseal_guest(root, "commands.json", trace)

    def test_accepts_exact_fresh_guest_and_child_window(self):
        root, _report, child_audit = self.fixture()
        result = self.audit(root, child_audit)
        self.assertEqual("accepted_fresh_recents_guest_not_runtime_or_hardware_qualification",
                         result["status"])
        self.assertEqual(self.container_run, result["run"])
        self.assertEqual(self.recents_run, result["recents_run"])

    def test_required_phone_epoch_preserves_original_core_process_inventory(self):
        expected = {"system_server", "com.android.systemui", "com.android.launcher3", "com.android.phone"}
        self.assertEqual(acceptance.PROTECTED, expected)
        root, _report, child_audit = self.fixture()
        before = base.common.load(root / "guest/before.json")
        self.assertEqual(set(before["protected_processes"]), expected)
        self.assertEqual(len({epoch["pid"] for epoch in before["protected_processes"].values()}), 4)
        self.assertEqual(self.audit(root, child_audit)["recents_run"], self.recents_run)

    def test_phone_epoch_omitted_from_either_summary_is_rejected(self):
        for side in ("before", "after"):
            with self.subTest(side=side):
                root, _report, child_audit = self.fixture()
                state = base.common.load(root / ("guest/" + side + ".json"))
                del state["protected_processes"]["com.android.phone"]
                self.reseal_guest(root, side + ".json", state)
                with self.assertRaisesRegex(acceptance.EvidenceError, "Malformed fresh-Recents guest state"):
                    self.audit(root, child_audit)

    def test_phone_raw_pair_cannot_be_omitted_while_summaries_claim_continuity(self):
        for side in (0, 1):
            with self.subTest(side=side):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                pairs = [index for index, row in enumerate(trace)
                         if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
                del trace[pairs[side]:pairs[side] + 2]
                self.retime_around_child(root, trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "epochs are missing, extra or unpaired"):
                    self.audit(root, child_audit)

    def test_duplicate_phone_pid_alias_cannot_pass_four_role_state_and_raw_audit(self):
        root, _report, child_audit = self.fixture()
        for side in ("before", "after"):
            state = base.common.load(root / ("guest/" + side + ".json"))
            state["protected_processes"]["com.android.phone"]["pid"] = 202
            self.reseal_guest(root, side + ".json", state)
        trace = base.common.load(root / "guest/commands.json")
        for index, row in enumerate(trace):
            if row.get("argv", [])[-3:] != ["shell", "pidof", "com.android.phone"]:
                continue
            row["output"] = "202\n"
            trace[index + 1]["argv"][-1] = "/proc/202/stat"
            trace[index + 1]["output"] = trace[index + 1]["output"].replace("404 (", "202 (")
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "ambiguous PIDs"):
            self.audit(root, child_audit)

    def test_duplicate_phone_raw_epoch_observation_is_rejected(self):
        for side in (0, 1):
            with self.subTest(side=side):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                pairs = [index for index, row in enumerate(trace)
                         if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
                index = pairs[side]
                trace[index:index] = copy.deepcopy(trace[index:index + 2])
                self.retime_around_child(root, trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "epochs are missing, extra or unpaired"):
                    self.audit(root, child_audit)

    def test_phone_raw_restart_and_pid_reuse_cannot_hide_behind_stable_summaries(self):
        for new_pid, new_ticks in ((505, 1005), (404, 1005)):
            with self.subTest(pid=new_pid, start_ticks=new_ticks):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                pairs = [index for index, row in enumerate(trace)
                         if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
                index = pairs[-1]
                trace[index]["output"] = str(new_pid) + "\n"
                trace[index + 1]["argv"][-1] = f"/proc/{new_pid}/stat"
                trace[index + 1]["output"] = f"{new_pid} (com.android.phone) S " + \
                    " ".join(["1"] * 18 + [str(new_ticks)]) + "\n"
                self.reseal_guest(root, "commands.json", trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "Raw protected-process epochs changed"):
                    self.audit(root, child_audit)

    def test_phone_raw_restart_is_rejected_when_both_summaries_are_resealed_to_new_epoch(self):
        root, _report, child_audit = self.fixture()
        replacement = {"pid": 404, "start_ticks": 1005}
        for side in ("before", "after"):
            state = base.common.load(root / ("guest/" + side + ".json"))
            state["protected_processes"]["com.android.phone"] = replacement
            self.reseal_guest(root, side + ".json", state)
        trace = base.common.load(root / "guest/commands.json")
        pairs = [index for index, row in enumerate(trace)
                 if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
        trace[pairs[-1] + 1]["output"] = trace[pairs[-1] + 1]["output"].replace("1004", "1005")
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "Raw protected-process epochs changed"):
            self.audit(root, child_audit)

    def test_phone_raw_stat_must_be_paired_and_terminal_epoch_must_follow_child(self):
        for mutation in ("unpaired", "early_terminal"):
            with self.subTest(mutation=mutation):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                pairs = [index for index, row in enumerate(trace)
                         if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
                index = pairs[-1]
                if mutation == "unpaired":
                    trace[index + 1]["argv"][-1] = "/proc/505/stat"
                else:
                    pair = trace[index:index + 2]; del trace[index:index + 2]
                    first_install = next(offset for offset, row in enumerate(trace)
                                         if "install" in row.get("argv", []))
                    trace[first_install:first_install] = pair
                self.retime_around_child(root, trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "Unpaired protected process|bracket"):
                    self.audit(root, child_audit)

    def test_recents_requires_unique_current_home_proof_before_child(self):
        for attack in ("missing", "duplicate", "settings_focus", "before_home", "other_display"):
            with self.subTest(attack=attack):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                activity = next(index for index, row in enumerate(trace)
                                if row.get("argv", [])[-3:] ==
                                ["dumpsys", "activity", "activities"])
                window = next(index for index, row in enumerate(trace)
                              if row.get("argv", [])[-3:] == ["dumpsys", "window", "windows"])
                home = next(index for index, row in enumerate(trace)
                            if row.get("argv", [])[-7:] ==
                            ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
                if attack == "missing":
                    trace.pop(activity)
                elif attack == "duplicate":
                    trace[activity:activity] = [copy.deepcopy(trace[activity]),
                                                copy.deepcopy(trace[window])]
                elif attack == "settings_focus":
                    trace[activity]["output"] = base.phone_home_activities().replace(
                        "mCurrentFocus=Window{123abc u0 " + base.HOME_FULL_COMPONENT,
                        "mCurrentFocus=Window{123abc u0 " + acceptance.fresh.SETTINGS)
                elif attack == "other_display":
                    trace[window]["output"] = base.phone_home_windows(display=2, focused=2)
                else:
                    row = trace.pop(home)
                    window = next(index for index, item in enumerate(trace)
                                  if item.get("argv", [])[-3:] ==
                                  ["dumpsys", "window", "windows"])
                    trace.insert(window + 1, row)
                self.retime_around_child(root, trace)
                with self.assertRaises(ValueError):
                    self.audit(root, child_audit)

    def test_recents_home_proof_cannot_exceed_fifteen_seconds(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        self.retime_around_child(root, trace)
        trace = base.common.load(root / "guest/commands.json")
        home = next(index for index, row in enumerate(trace) if row.get("argv", [])[-7:] ==
                    ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
        window = next(index for index, row in enumerate(trace) if row.get("argv", [])[-3:] ==
                      ["dumpsys", "window", "windows"])
        delay = 15_000_000_001
        trace[window]["ended_monotonic_ns"] = trace[home]["ended_monotonic_ns"] + delay
        cursor = trace[window]["ended_monotonic_ns"] + 1
        for row in trace[window + 1:]:
            duration = row["ended_monotonic_ns"] - row["started_monotonic_ns"]
            row["started_monotonic_ns"] = cursor
            row["ended_monotonic_ns"] = cursor + duration
            cursor = row["ended_monotonic_ns"] + 2
        self.retime_around_child(root, trace, sync_prelaunch=False)
        # retime_around_child normalizes durations, so restore the deliberate
        # bounded-wait violation after it has moved the child interval.
        trace = base.common.load(root / "guest/commands.json")
        home = next(index for index, row in enumerate(trace) if row.get("argv", [])[-7:] ==
                    ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
        window = next(index for index, row in enumerate(trace) if row.get("argv", [])[-3:] ==
                      ["dumpsys", "window", "windows"])
        trace[window]["ended_monotonic_ns"] = trace[home]["ended_monotonic_ns"] + delay
        cursor = trace[window]["ended_monotonic_ns"] + 1
        for row in trace[window + 1:]:
            duration = row["ended_monotonic_ns"] - row["started_monotonic_ns"]
            row["started_monotonic_ns"] = cursor
            row["ended_monotonic_ns"] = cursor + duration
            cursor = row["ended_monotonic_ns"] + 2
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "fifteen seconds"):
            self.audit(root, child_audit)

    def test_prelaunch_inventory_and_reviewed_sources_are_native_evidence(self):
        root, _report, child_audit = self.fixture()
        raw = base.common.load(root / "guest/prelaunch-userdata.json")
        raw["inventory"][0]["children"] = ["seeded.img"]
        self.reseal_prelaunch(root, raw)
        with self.assertRaisesRegex(acceptance.EvidenceError, "timeline/inventory"):
            self.audit(root, child_audit)

        root, _report, child_audit = self.fixture()
        raw = base.common.load(root / "guest/prelaunch-userdata.json")
        raw["authority"]["runner"]["sha256"] = "0" * 64
        self.reseal_prelaunch(root, raw)
        with self.assertRaisesRegex(acceptance.EvidenceError, "unreviewed prelaunch"):
            self.audit(root, child_audit)

    def test_prelaunch_record_must_be_canonical_and_immediately_before_launch(self):
        root, _report, child_audit = self.fixture()
        raw = base.common.load(root / "guest/prelaunch-userdata.json")
        self.reseal_prelaunch(root, raw, canonical=False)
        with self.assertRaisesRegex(acceptance.EvidenceError, "unreviewed prelaunch"):
            self.audit(root, child_audit)

        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        local_index = next(index for index, row in enumerate(trace)
                           if row.get("kind") == "local_evidence")
        manifest_index = local_index - 1
        trace[manifest_index], trace[local_index] = trace[local_index], trace[manifest_index]
        for index, row in enumerate(trace):
            row["started_monotonic_ns"] = 6 + index * 3
            row["ended_monotonic_ns"] = 7 + index * 3
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "immediately precede"):
            self.audit(root, child_audit)

    def test_pre_success_boot_timeout_and_nonzero_attempts_are_auditable(self):
        for ordinal, attempt in enumerate(("timeout", "nonzero")):
            with self.subTest(attempt=attempt):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                boot_index = next(index for index, row in enumerate(trace)
                                  if row.get("argv", [])[-2:] ==
                                  ["getprop", "sys.boot_completed"])
                inspection = copy.deepcopy(trace[boot_index - 1])
                boot = copy.deepcopy(trace[boot_index])
                if attempt == "timeout":
                    boot = {"argv": boot["argv"], "returncode": None, "timed_out": True,
                            "timeout_seconds": 10, "started_monotonic_ns": 1,
                            "ended_monotonic_ns": 10_000_000_001, "output": ""}
                else:
                    boot["returncode"] = 1
                    boot["output"] = "error: device offline\n"
                trace[boot_index:boot_index] = [boot, inspection]
                self.retime_around_child(root, trace)
                result = self.audit(root, child_audit)
                self.assertEqual(
                    "accepted_fresh_recents_guest_not_runtime_or_hardware_qualification",
                    result["status"])

    def test_boot_timeout_must_record_its_full_elapsed_interval(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        boot_index = next(index for index, row in enumerate(trace)
                          if row.get("argv", [])[-2:] ==
                          ["getprop", "sys.boot_completed"])
        inspection = copy.deepcopy(trace[boot_index - 1])
        boot = {"argv": trace[boot_index]["argv"], "returncode": None,
                "timed_out": True, "timeout_seconds": 10,
                "started_monotonic_ns": 1, "ended_monotonic_ns": 2,
                "output": ""}
        trace[boot_index:boot_index] = [boot, inspection]
        self.retime_around_child(root, trace)
        trace = base.common.load(root / "guest/commands.json")
        timed_out = next(row for row in trace if row.get("timed_out") is True)
        timed_out["ended_monotonic_ns"] = timed_out["started_monotonic_ns"] + 1
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "timed-out"):
            self.audit(root, child_audit)

    def test_seeded_setting_command_is_rejected_after_resealing(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        trace.insert(-2, self.row(prefix + ["shell", "settings", "--user", "0", "put", "secure",
                                                   "wonad_external_desktop_enabled", "1"], 3001))
        for index, row in enumerate(trace):
            row["started_monotonic_ns"] = index * 2 + 1
            row["ended_monotonic_ns"] = index * 2 + 2
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "settings seeding"):
            self.audit(root, child_audit)

    def test_forged_installed_summary_is_rejected(self):
        root, _report, child_audit = self.fixture()
        before = base.common.load(root / "guest/before.json")
        before["installed"][acceptance.APP]["path"] = "/forged/base.apk"
        self.reseal_guest(root, "before.json", before)
        with self.assertRaisesRegex(acceptance.EvidenceError, "Installed APK identity"):
            self.audit(root, child_audit)

    def test_missing_raw_os_observation_is_rejected(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        path = next(iter(acceptance.GUEST_OS_PATHS))
        trace.remove(next(row for row in trace if row.get("argv", [])[-2:] ==
                          ["sha256sum", path]))
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "Raw guest OS bytes changed"):
            self.audit(root, child_audit)

    def test_child_outside_setup_terminal_window_is_rejected(self):
        root, _report, child_audit = self.fixture()
        child = base.common.load(root / "recents/commands.json")
        child[0]["started_monotonic_ns"] = child[0]["ended_monotonic_ns"] = 999999
        (root / "recents/commands.json").write_bytes(base.common.canonical(child))
        with self.assertRaisesRegex(acceptance.EvidenceError, "outside the fresh"):
            self.audit(root, child_audit)

    def test_substituted_child_audit_summary_is_rejected(self):
        root, _report, child_audit = self.fixture()
        changed = copy.deepcopy(child_audit); changed["run"] = "f" * 32
        with self.assertRaisesRegex(acceptance.EvidenceError, "audit summary"):
            self.audit(root, changed)

    def test_reused_child_boot_is_rejected(self):
        root, _report, child_audit = self.fixture()
        child = base.common.load(root / "recents/report.json")
        child["boot_id"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        (root / "recents/report.json").write_bytes(base.common.canonical(child))
        report = base.common.load(root / "report.json")
        report["recents_report"].update(base.common.file_ref(root / "recents/report.json"))
        report["recents_audit"]["report_sha256"] = report["recents_report"]["sha256"]
        (root / "report.json").write_bytes(base.common.canonical(report))
        child_audit["report_sha256"] = report["recents_report"]["sha256"]
        with self.assertRaisesRegex(acceptance.EvidenceError, "another image/container/boot"):
            self.audit(root, child_audit)

    def test_foreign_container_inspection_is_rejected(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                       ["docker", "container", "inspect"])
        info = json.loads(inspect["output"]); info[0]["Id"] = "f" * 64
        inspect["output"] = json.dumps(info)
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
            self.audit(root, child_audit)

    def test_launch_isolation_must_be_corroborated_by_inspect(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                       ["docker", "container", "inspect"])
        info = json.loads(inspect["output"])
        info[0]["HostConfig"]["CapDrop"] = []
        inspect["output"] = json.dumps(info)
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
            self.audit(root, child_audit)

    def test_running_inspections_cannot_be_false_or_omitted(self):
        for attack in ("false", "omitted"):
            with self.subTest(attack=attack):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                inspect_index = next(index for index, row in enumerate(trace)
                                     if row.get("argv", [])[:3] ==
                                     ["docker", "container", "inspect"])
                if attack == "false":
                    info = json.loads(trace[inspect_index]["output"])
                    info[0]["State"]["Running"] = False
                    trace[inspect_index]["output"] = json.dumps(info)
                else:
                    del trace[inspect_index]
                self.retime_around_child(root, trace)
                with self.assertRaisesRegex(acceptance.EvidenceError,
                                            "continuously running|boot attempt|boot polling"):
                    self.audit(root, child_audit)

    def test_docker_ulimits_are_exact_by_unique_name_not_list_order(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        for row in trace:
            if row.get("argv", [])[:3] == ["docker", "container", "inspect"]:
                info = json.loads(row["output"])
                info[0]["HostConfig"]["Ulimits"].reverse()
                row["output"] = json.dumps(info)
        self.reseal_guest(root, "commands.json", trace)
        self.assertEqual(
            "accepted_fresh_recents_guest_not_runtime_or_hardware_qualification",
            self.audit(root, child_audit)["status"])

        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                       ["docker", "container", "inspect"])
        info = json.loads(inspect["output"])
        info[0]["HostConfig"]["Ulimits"][1]["Name"] = "core"
        inspect["output"] = json.dumps(info)
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
            self.audit(root, child_audit)

    def test_duplicate_mount_destination_cannot_be_hidden_by_dict_projection(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                       ["docker", "container", "inspect"])
        info = json.loads(inspect["output"])
        info[0]["Mounts"].insert(0, {
            "Destination": "/state", "Source": "/foreign", "RW": True,
        })
        inspect["output"] = json.dumps(info)
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
            self.audit(root, child_audit)

    def test_state_mount_must_be_the_exact_declared_bind(self):
        for mutation in ("type", "mode", "propagation", "binds"):
            with self.subTest(mutation=mutation):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                               ["docker", "container", "inspect"])
                info = json.loads(inspect["output"])
                if mutation == "type":
                    info[0]["Mounts"][0]["Type"] = "volume"
                elif mutation == "mode":
                    info[0]["Mounts"][0]["Mode"] = "rw"
                elif mutation == "propagation":
                    info[0]["Mounts"][0]["Propagation"] = "rshared"
                else:
                    info[0]["HostConfig"]["Binds"] = ["/foreign:/state:rw,Z"]
                inspect["output"] = json.dumps(info)
                self.reseal_guest(root, "commands.json", trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
                    self.audit(root, child_audit)

    def test_inspect_cannot_hide_privilege_or_resource_expansion(self):
        attacks = {
            "CapAdd": ["SYS_ADMIN"],
            "DeviceRequests": [{"Driver": "", "Count": -1, "Capabilities": [["gpu"]]}],
            "DeviceCgroupRules": ["c 1:3 rwm"],
            "PidMode": "host",
            "IpcMode": "host",
            "UTSMode": "host",
            "UsernsMode": "host",
            "CgroupnsMode": "host",
            "VolumesFrom": ["foreign:rw"],
            "PublishAllPorts": True,
            "ReadonlyRootfs": True,
            "MemorySwap": -1,
            "OomKillDisable": True,
            "PortBindings": False,
            "MemoryReservation": False,
            "RestartPolicy": {"Name": "no", "MaximumRetryCount": False},
        }
        for field, forged in attacks.items():
            with self.subTest(field=field):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                               ["docker", "container", "inspect"])
                info = json.loads(inspect["output"])
                info[0]["HostConfig"][field] = forged
                inspect["output"] = json.dumps(info)
                self.reseal_guest(root, "commands.json", trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
                    self.audit(root, child_audit)
        for field in ("PortBindings", "MemoryReservation", "RestartPolicy"):
            with self.subTest(missing=field):
                root, _report, child_audit = self.fixture()
                trace = base.common.load(root / "guest/commands.json")
                inspect = next(row for row in trace if row.get("argv", [])[:3] ==
                               ["docker", "container", "inspect"])
                info = json.loads(inspect["output"])
                del info[0]["HostConfig"][field]
                inspect["output"] = json.dumps(info)
                self.reseal_guest(root, "commands.json", trace)
                with self.assertRaisesRegex(acceptance.EvidenceError, "identity/isolation"):
                    self.audit(root, child_audit)

    def test_offline_identity_reads_must_precede_launch(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        moved = trace[:2]
        trace = trace[2:] + moved
        self.retime_around_child(root, trace, sync_prelaunch=False)
        with self.assertRaisesRegex(acceptance.EvidenceError,
                                    "verification/manifest.*before"):
            self.audit(root, child_audit)

    def test_every_fresh_install_must_report_success(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        install = next(row for row in trace if "install" in row.get("argv", []))
        install["output"] = "Package installed\n"
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "did not return Success"):
            self.audit(root, child_audit)

    def test_extra_installed_path_hash_is_rejected(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        terminal_inspect = [index for index, row in enumerate(trace)
                            if row.get("argv", [])[:3] ==
                            ["docker", "container", "inspect"]][-2]
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        path = "/data/app/extra/base.apk"
        trace.insert(terminal_inspect, self.row(
            prefix + ["shell", "sha256sum", path], 1, "f" * 64 + "  " + path + "\n"))
        self.retime_around_child(root, trace)
        with self.assertRaisesRegex(acceptance.EvidenceError,
                                    "missing, extra or substituted"):
            self.audit(root, child_audit)

    def test_coherent_non_installed_apk_path_is_rejected(self):
        root, _report, child_audit = self.fixture()
        old, forged = "/data/app/conformance/base.apk", "/forged/base.apk"
        for name in ("before.json", "after.json"):
            state = base.common.load(root / "guest" / name)
            state["installed"][acceptance.APP]["path"] = forged
            if name == "after.json":
                state["packages"][acceptance.APP] = forged
            self.reseal_guest(root, name, state)
        trace = base.common.load(root / "guest/commands.json")
        for row in trace:
            if "argv" in row:
                row["argv"] = [forged if item == old else item for item in row["argv"]]
            if "output" in row:
                row["output"] = row["output"].replace(old, forged)
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "Installed APK identity"):
            self.audit(root, child_audit)

    def test_boot_must_reach_one_and_keyguard_observation_is_required(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        boot = next(row for row in trace if row.get("argv", [])[-2:] ==
                    ["getprop", "sys.boot_completed"])
        boot["output"] = "0\n"
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "completed boot"):
            self.audit(root, child_audit)

        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        trace[:] = [row for row in trace if row.get("argv", [])[-4:] !=
                    ["dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"]]
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "keyguard"):
            self.audit(root, child_audit)

    def test_preinstall_package_presence_is_rejected(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        checks = [row for row in trace if row.get("argv", [])[-4:] ==
                  ["shell", "pm", "path", acceptance.APP]]
        checks[1]["output"] = "package:/data/app/preexisting/base.apk\n"
        checks[1]["returncode"] = 0
        self.reseal_guest(root, "commands.json", trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "preinstall absence"):
            self.audit(root, child_audit)

    def test_extra_allowed_tap_is_rejected(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        tap_index = next(index for index, row in enumerate(trace)
                         if "tap" in row.get("argv", []))
        extra = copy.deepcopy(trace[tap_index])
        extra["argv"][-2:] = ["1", "1"]
        trace.insert(tap_index + 1, extra)
        self.retime_around_child(root, trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "genuine SystemUI consent"):
            self.audit(root, child_audit)

    def test_protected_event_readback_cannot_precede_child(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        event_index = next(index for index, row in enumerate(trace)
                           if row.get("evidence") == "protected-events.txt")
        event = trace.pop(event_index)
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        wanted = [["shell", "pm", "path", package]
                  for package in (acceptance.APP, acceptance.FIXTURE, acceptance.FAULT)]
        starts = [index for index in range(len(trace) - 2)
                  if all(trace[index + offset].get("argv", [])[:len(prefix)] == prefix
                         for offset in range(3)) and
                  [trace[index + offset]["argv"][len(prefix):] for offset in range(3)] == wanted]
        trace.insert(starts[-1] - 1, event)
        self.retime_around_child(root, trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "protected-event"):
            self.audit(root, child_audit)

    def test_terminal_process_epochs_must_follow_child(self):
        root, _report, child_audit = self.fixture()
        trace = base.common.load(root / "guest/commands.json")
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        wanted = [["shell", "pm", "path", package]
                  for package in (acceptance.APP, acceptance.FIXTURE, acceptance.FAULT)]
        starts = [index for index in range(len(trace) - 2)
                  if all(trace[index + offset].get("argv", [])[:len(prefix)] == prefix
                         for offset in range(3)) and
                  [trace[index + offset]["argv"][len(prefix):] for offset in range(3)] == wanted]
        terminal = starts[-1]
        second_pairs = []
        for name in sorted(acceptance.PROTECTED):
            indices = [index for index, row in enumerate(trace)
                       if row.get("argv") == prefix + ["shell", "pidof", name]]
            second_pairs.extend([trace[indices[1]], trace[indices[1] + 1]])
        trace = [row for row in trace if all(row is not moved for moved in second_pairs)]
        terminal = [index for index in range(len(trace) - 2)
                    if all(trace[index + offset].get("argv", [])[:len(prefix)] == prefix
                           for offset in range(3)) and
                    [trace[index + offset]["argv"][len(prefix):]
                     for offset in range(3)] == wanted][-1]
        trace[terminal:terminal] = second_pairs
        self.retime_around_child(root, trace)
        with self.assertRaisesRegex(acceptance.EvidenceError, "bracket"):
            self.audit(root, child_audit)


if __name__ == "__main__":
    unittest.main()
