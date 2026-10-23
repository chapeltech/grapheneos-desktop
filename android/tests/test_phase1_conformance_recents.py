"""Hostile-evidence tests for the dedicated Phase-1 Recents lane.

These are format/semantic tests, not emulator qualification.  They make sure a
producer PASS, a surviving UI label, or a recycled task/display identifier
cannot satisfy the independent auditor.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))
import phase1_conformance_recents_acceptance as audit
import phase1_conformance_recents as producer


UIDS = {audit.APP: 10180, audit.FIXTURE: 10181,
        audit.LAUNCHER: 10146, audit.SYSTEMUI: 10148}


class PackageIdentityTests(unittest.TestCase):
    @staticmethod
    def raw(app=10180, fixture=10181, launcher=10146, systemui=10148):
        return ("package:%s uid:%d\n" % (audit.APP, app) +
                "package:%s uid:%d\n" % (audit.FIXTURE, fixture) +
                "package:%s uid:%d\n" % (audit.LAUNCHER, launcher) +
                "package:%s uid:%d\n" % (audit.SYSTEMUI, systemui))

    def test_client_system_uid_is_not_an_ordinary_application_identity(self):
        with self.assertRaisesRegex(audit.EvidenceError, "ordinary application"):
            audit.package_uids(self.raw(app=1000, fixture=10001,
                                        launcher=1002, systemui=1001))

    def test_client_uid_rejects_sdk_sandbox_isolated_and_cross_user_ranges(self):
        for uid in (20000, 99000, 110180):
            with self.subTest(uid=uid), self.assertRaisesRegex(
                    audit.EvidenceError, "ordinary application"):
                audit.package_uids(self.raw(app=uid))

    def test_package_uid_evidence_is_complete_unique_and_canonical(self):
        self.assertEqual(UIDS, audit.package_uids(self.raw()))
        for raw in (self.raw().removesuffix("\n"),
                    self.raw() + "package:extra uid:10190\n",
                    self.raw().replace("package:%s uid:10180\n" % audit.APP, ""),
                    self.raw(fixture=10180)):
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.package_uids(raw)

    def test_real_producer_scopes_forward_and_reverse_uid_reads_to_user_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint",
                Path(temporary), 30)
            outputs = {
                ("cmd", "package", "list", "packages", "-U", "--user", "0", audit.APP):
                    "package:%s uid:10180" % audit.APP,
                ("cmd", "package", "list", "packages", "-U", "--user", "0", audit.FIXTURE):
                    "package:%s uid:10181" % audit.FIXTURE,
                ("cmd", "package", "list", "packages", "-U", "--user", "0", audit.LAUNCHER):
                    "package:%s uid:10146" % audit.LAUNCHER,
                ("cmd", "package", "list", "packages", "-U", "--user", "0", audit.SYSTEMUI):
                    "package:%s uid:10148" % audit.SYSTEMUI,
                ("cmd", "package", "list", "packages", "-U", "--user", "0", "--uid", "10180"):
                    "package:%s uid:10180" % audit.APP,
                ("cmd", "package", "list", "packages", "-U", "--user", "0", "--uid", "10181"):
                    "package:%s uid:10181" % audit.FIXTURE,
            }
            calls = []
            def run(argv, **_kwargs):
                command = tuple(argv[7:]); calls.append(command)
                return mock.Mock(returncode=0, stdout=outputs[command] + "\n")
            with mock.patch.object(producer.subprocess, "run", side_effect=run):
                self.assertEqual(UIDS, value.package_identities())
            self.assertEqual(6, len(calls))
            self.assertTrue(all(call[5:7] == ("--user", "0") for call in calls))
            self.assertEqual([0, 1, 2, 3, 4, 5], value.trace[-1]["inputs"])
            prefix = ["docker", "exec", value.container, "adb", "-s", audit.SERIAL, "shell"]
            self.assertTrue(all(row["argv"][:7] == prefix for row in value.trace[:-1]))

    def test_auditor_replays_exact_forward_and_singleton_reverse_uid_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            relative = "identity.txt"
            (directory / relative).write_text(self.raw())
            container = "a" * 64
            prefix = ["docker", "exec", container, "adb", "-s", audit.SERIAL,
                      "shell", "cmd", "package", "list", "packages", "-U",
                      "--user", "0"]
            packages = (audit.APP, audit.FIXTURE, audit.LAUNCHER, audit.SYSTEMUI)
            trace = [{"argv": prefix + [package], "returncode": 0,
                      "output": self.raw().splitlines()[index] + "\n"}
                     for index, package in enumerate(packages)]
            trace += [{"argv": prefix + ["--uid", str(UIDS[package])], "returncode": 0,
                       "output": "package:%s uid:%d\n" % (package, UIDS[package])}
                      for package in (audit.APP, audit.FIXTURE)]
            derived = {"sequence": 6, "inputs": list(range(6)), "evidence": relative,
                       "output_sha256": audit.sha256(directory / relative)}
            evidence = {relative: audit.file_ref(directory / relative)}
            self.assertEqual(UIDS, audit.package_identity_derivation(
                trace, derived, evidence, directory, container))

            shared = copy.deepcopy(trace)
            shared[4]["output"] += "package:%s uid:10180\n" % audit.FIXTURE
            with self.assertRaisesRegex(audit.EvidenceError, "shared|reverse-bound"):
                audit.package_identity_derivation(shared, derived, evidence, directory, container)
            unscoped = copy.deepcopy(trace)
            unscoped[0]["argv"] = unscoped[0]["argv"][:-3] + [audit.APP]
            with self.assertRaisesRegex(audit.EvidenceError, "exact PackageManager"):
                audit.package_identity_derivation(unscoped, derived, evidence, directory, container)
            extra = copy.deepcopy(trace) + [copy.deepcopy(trace[0])]
            late = {**derived, "sequence": 7}
            with self.assertRaisesRegex(audit.EvidenceError, "Unpaired"):
                audit.package_identity_derivation(extra, late, evidence, directory, container)



# Actual stock PackageManager substring-query output retained before host fixes:
# packet5 Recents3 commands.json SHA aa3ea5f0483bc0dac5ce5eb79c9094a0281b50cc1fa14aba57d04d8034e9740c,
# row33. The other forward/reverse rows below remain synthetic host fixtures.
ACTUAL_SYSTEMUI_SUBSTRING_QUERY = "package:com.android.systemui.auto_generated_rro_vendor__ uid:10063\npackage:com.android.systemui.emulation.pixel_fold uid:10031\npackage:com.android.systemui.emulation.pixel_8_pro uid:10015\npackage:com.android.systemui.emulation.pixel_6_pro uid:10020\npackage:com.android.systemui.emulation.pixel_4a uid:10048\npackage:com.android.systemui.emulation.pixel_3a_xl uid:10058\npackage:com.android.systemui.emulation.pixel_3a uid:10002\npackage:com.android.systemui.emulation.pixel_3 uid:10055\npackage:com.android.systemui uid:10148\npackage:com.android.systemui.emulation.pixel_7 uid:10001\npackage:com.android.systemui.emulation.pixel_6 uid:10021\npackage:com.android.systemui.emulation.pixel_4_xl uid:10007\npackage:com.android.systemui.emulation.pixel_7_pro uid:10038\npackage:com.android.systemui.emulation.pixel_5 uid:10011\npackage:com.android.systemui.emulation.pixel_4 uid:10029\npackage:com.android.systemui.emulation.pixel_8a uid:10010\npackage:com.android.systemui.emulation.pixel_3_xl uid:10039\npackage:com.android.systemui.emulation.pixel_6a uid:10018\npackage:com.android.systemui.accessibility.accessibilitymenu uid:10153\npackage:com.android.systemui.emulation.pixel_7a uid:10049\npackage:com.android.systemui.emulation.pixel_8 uid:10005\n"


class PackageSubstringQueryTests(unittest.TestCase):
    @staticmethod
    def hostile_outputs():
        exact = "package:%s uid:10148\n" % audit.SYSTEMUI
        raw = ACTUAL_SYSTEMUI_SUBSTRING_QUERY
        return (
            raw.replace(exact, ""),
            raw + exact,
            raw + "package:%s uid:10149\n" % audit.SYSTEMUI,
            raw + raw.splitlines()[0] + "\n",
            raw + "package:com.android.systemui.emulation.pixel_8 uid:10190\n",
            raw + "PackageManager warning\n",
            raw + "package:invalid-name uid:10001\n",
            raw + "package:other.valid uid:0\n",
            raw + "package:other.valid uid:010001\n",
            raw + "package:other.valid uid:200000\n",
            raw.replace("uid:10148", "uid:true"),
            raw.replace("\n", "\r\n"),
            " " + raw,
            raw + "\n",
        )

    def test_actual_twenty_one_rows_select_only_exact_requested_package(self):
        self.assertEqual(21, len(ACTUAL_SYSTEMUI_SUBSTRING_QUERY.splitlines()))
        self.assertEqual("package:%s uid:10148" % audit.SYSTEMUI,
                         audit.package_manager_uid_row(ACTUAL_SYSTEMUI_SUBSTRING_QUERY, audit.SYSTEMUI))
        self.assertEqual("package:%s uid:10148" % audit.SYSTEMUI,
                         audit.package_manager_uid_row(
                             ACTUAL_SYSTEMUI_SUBSTRING_QUERY.removesuffix("\n"), audit.SYSTEMUI))

    def test_all_rows_are_strict_unique_and_exact_package_is_required(self):
        for index, raw in enumerate(self.hostile_outputs()):
            with self.subTest(case=index), self.assertRaises(audit.EvidenceError):
                audit.package_manager_uid_row(raw, audit.SYSTEMUI)

    @staticmethod
    def outputs(shared_reverse=False):
        packages = (audit.APP, audit.FIXTURE, audit.LAUNCHER, audit.SYSTEMUI)
        result = {( "cmd", "package", "list", "packages", "-U", "--user", "0", package):
                  "package:%s uid:%d\n" % (package, UIDS[package]) for package in packages}
        result[("cmd", "package", "list", "packages", "-U", "--user", "0", audit.SYSTEMUI)] = \
            ACTUAL_SYSTEMUI_SUBSTRING_QUERY
        for package in (audit.APP, audit.FIXTURE):
            result[("cmd", "package", "list", "packages", "-U", "--user", "0",
                    "--uid", str(UIDS[package]))] = "package:%s uid:%d\n" % (package, UIDS[package])
        if shared_reverse:
            result[("cmd", "package", "list", "packages", "-U", "--user", "0",
                    "--uid", str(UIDS[audit.APP]))] += "package:other.shared uid:10180\n"
        return result

    def producer_identity(self, directory, shared_reverse=False, systemui_raw=None):
        value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
            "11111111-2222-3333-4444-555555555555", "fingerprint", directory, 30)
        outputs = self.outputs(shared_reverse)
        if systemui_raw is not None:
            outputs[("cmd", "package", "list", "packages", "-U", "--user", "0",
                     audit.SYSTEMUI)] = systemui_raw
        def run(argv, **_kwargs):
            return mock.Mock(returncode=0, stdout=outputs[tuple(argv[7:])])
        with mock.patch.object(producer.subprocess, "run", side_effect=run):
            result = value.package_identities()
        return value, result

    def test_real_producer_accepts_stock_query_and_retains_all_raw_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            value, result = self.producer_identity(Path(temporary))
            self.assertEqual(UIDS, result)
            self.assertEqual(ACTUAL_SYSTEMUI_SUBSTRING_QUERY, value.trace[3]["output"])
            self.assertEqual(PackageIdentityTests.raw(),
                             (Path(temporary) / "identity/package-uids.txt").read_text())

    def test_producer_rejects_all_hostile_raw_rows_without_shell_stripping(self):
        for index, raw in enumerate(self.hostile_outputs()):
            with self.subTest(case=index), tempfile.TemporaryDirectory() as temporary, \
                 self.assertRaises(audit.EvidenceError):
                self.producer_identity(Path(temporary), systemui_raw=raw)

    def derivation_fixture(self, directory):
        relative, container = "identity.txt", "a" * 64
        (directory / relative).write_text(PackageIdentityTests.raw())
        packages = (audit.APP, audit.FIXTURE, audit.LAUNCHER, audit.SYSTEMUI)
        prefix = ["docker", "exec", container, "adb", "-s", audit.SERIAL, "shell"]
        outputs = self.outputs()
        suffixes = [("cmd", "package", "list", "packages", "-U", "--user", "0", package)
                    for package in packages]
        suffixes += [("cmd", "package", "list", "packages", "-U", "--user", "0", "--uid",
                      str(UIDS[package])) for package in (audit.APP, audit.FIXTURE)]
        trace = [{"argv": prefix + list(command), "returncode": 0, "output": outputs[command]}
                 for command in suffixes]
        derived = {"sequence": 6, "inputs": list(range(6)), "evidence": relative,
                   "output_sha256": audit.sha256(directory / relative)}
        evidence = {relative: audit.file_ref(directory / relative)}
        return trace, derived, evidence, container

    def test_independent_auditor_rederives_exact_uid_from_actual_stock_query(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trace, derived, evidence, container = self.derivation_fixture(directory)
            self.assertEqual(UIDS, audit.package_identity_derivation(
                trace, derived, evidence, directory, container))

    def test_independent_auditor_rejects_malformed_duplicate_and_missing_exact_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trace, derived, evidence, container = self.derivation_fixture(directory)
            for index, raw in enumerate(self.hostile_outputs()):
                changed = copy.deepcopy(trace)
                changed[3]["output"] = raw
                with self.subTest(case=index), self.assertRaises(audit.EvidenceError):
                    audit.package_identity_derivation(changed, derived, evidence, directory, container)

    def test_forward_substring_tolerance_does_not_weaken_reverse_uid_singleton(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(
                ValueError, "shared|not owned"):
            self.producer_identity(Path(temporary), shared_reverse=True)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            trace, derived, evidence, container = self.derivation_fixture(directory)
            trace[4]["output"] += "package:other.shared uid:10180\n"
            with self.assertRaisesRegex(audit.EvidenceError, "reverse-bound|shared"):
                audit.package_identity_derivation(trace, derived, evidence, directory, container)


def menu(send=True):
    labels = ["Screenshot", "Split screen"] + (["Send to Wonad"] if send else [])
    return "<hierarchy>" + "".join(
        '<node package="com.android.launcher3" class="android.widget.LinearLayout" '
        'clickable="true" enabled="true" bounds="[80,%d][520,%d]">'
        '<node package="com.android.launcher3" resource-id="com.android.launcher3:id/text" '
        'text="%s" enabled="true" bounds="[100,%d][500,%d]" /></node>' %
        (180 + index * 120, 310 + index * 120, label, 200 + index * 120, 290 + index * 120)
        for index, label in enumerate(labels)) + "</hierarchy>"


def card(label):
    return ('<hierarchy><node package="com.android.launcher3" '
        'resource-id="com.android.launcher3:id/task_view_single" enabled="true" clickable="true">'
        '<node package="com.android.launcher3" resource-id="com.android.launcher3:id/snapshot" '
        'enabled="true" content-desc="%s" bounds="[173,350][907,1889]" />'
        '<node package="com.android.launcher3" resource-id="com.android.launcher3:id/icon" '
        'enabled="true" bounds="[173,258][493,350]" /></node></hierarchy>') % label


def record(component, task, display=0):
    return {"component": component, "task": task, "display": display,
            "instance": "%08x-1234-1234-1234-%012x" % (task, task),
            "left": 0, "top": 0, "right": 900, "bottom": 1000,
            "key_downs": 0, "pointer_downs": 0, "mouse_downs": 0}


def identity(row):
    task = row["task"]
    return {"task": task, "instance": row["instance"], "binder": "%07x" % (task + 1),
            "pid": 3000 + task, "uid": UIDS[audit.FIXTURE],
            "task_object": "%07x" % (task + 2), "activity_record": "%07x" % (task + 3)}


def display(display_id, slot):
    width, height, density = audit.DISPLAY_SPECS[slot]
    return {"display": display_id, "slot": slot,
            "unique_id": "virtual:com.android.emulator.multidisplay:" + str(1234561 + slot),
            "width": width, "height": height, "density": density,
            "flags": ["FLAG_SECURE", "FLAG_TRUSTED"]}


def shell(display_id, slot, token=None):
    return {"slot": slot, "display": display_id, "generation": 77,
            "token": token or 1000 + display_id, "task": 200 + slot,
            "task_object": "a%06x" % slot, "activity_record": "b%06x" % slot}


def home(display_id, slot, suffix=0):
    return {"slot": slot, "display": display_id, "task": 300 + slot + suffix,
            "task_object": "c%05x%x" % (slot, suffix),
            "activity_record": "d%05x%x" % (slot, suffix)}


def session_status(displays, state="ready", *, revision=100, topology=20, updated=200):
    ready = state == "ready"
    terminal = state in {"stopped", "failed"}
    blocked = state == "running"
    incarnations = [{"token": 1000 + display_id, "display_id": display_id,
        "identity_hint": 2000 + display_id, "shell_generation": 77,
        "density_dpi": row["density"], "bounds": [0, 0, row["width"], row["height"]]}
        for display_id, row in sorted(displays.items())]
    return {"schema": 1, "kind": "policy_free_conformance_runtime_v1",
        "run": "1" * 32, "mode": "runtime", "state": state,
        "phase": state if terminal else ("syncing-shells" if blocked else "ready"),
        "started_elapsed_ms": 100, "updated_elapsed_ms": updated,
        "api_version": 3, "capabilities": 0x7fff,
        "one_shot_api_coverage": {"mode": "full", "status": "not_run"},
        "runtime_readiness": {"ready": ready, "session_open": not terminal,
                              "reopen_required": False},
        "revocation_reason": None, "heartbeat_count": 2,
        "handshake": {"nonce": "2" * 32, "phase": "stop" if terminal else "checkpoint",
                      "result": "accepted"},
        "snapshot": {"generation": 77, "revision": revision, "topology_revision": topology,
                     "identity_epoch": 88, "focused_display_token": 0, "focused_token": 0,
                     "interaction_blocked": blocked, "display_incarnations": incarnations,
                     "tasks": []},
        "callbacks": {"onSnapshot": 4, "onCommand": 0, "onResult": 0, "onRevoked": 0},
        "facades": ["ExternalHomeActivity:valid", "ExternalShellActivity:valid"],
        "failure": "java.lang.IllegalStateException: runtime failed" if state == "failed" else None,
        "control_error": None}


def stage(name, displays=None, shells=None, homes=None, status="ready"):
    displays = displays if displays is not None else {2: display(2, 1), 3: display(3, 2), 4: display(4, 3)}
    shells = shells if shells is not None else {2: shell(2, 1), 3: shell(3, 2), 4: shell(4, 3)}
    homes = homes if homes is not None else {2: home(2, 1), 3: home(3, 2), 4: home(4, 3)}
    return {"name": name, "raw": {"hierarchy": "<hierarchy/>", "input": "",
             "windows": "", "activities": "", "log": "", "selection": None},
            "records": {}, "membership": {}, "identities": {}, "displays": displays,
            "shells": shells, "homes": homes,
            "status": session_status(displays, status),
            "broker_displays": {row["display"]: {"token": 1000 + row["display"],
                "display_id": row["display"], "identity_hint": 2000 + row["display"],
                "shell_generation": 77, "density_dpi": row["density"],
                "bounds": [0, 0, row["width"], row["height"]]} for row in displays.values()},
            "frames": {0: {"sha256": "phone-" + name, "pixels_sha256": "phone-" + name,
                            "known_colors": {}, "region_known_colors": {}},
                       **{row["slot"]: {"sha256": "%s-%d" % (name, row["slot"]),
                                               "pixels_sha256": "%s-%d" % (name, row["slot"]),
                                               "known_colors": {}, "region_known_colors": {}}
                          for row in displays.values()}},
            "focused_display": 0, "trace_start": 0, "trace_end": 1}


def add_task(value, component, task, display_id=0):
    row = record(component, task, display_id)
    value["records"][component] = row
    value["membership"][task] = display_id
    value["identities"][component] = identity(row)
    return row


def sync_runtime(value, state=None):
    state = state or value["status"]["state"]
    value["status"] = session_status(value["displays"], state)
    value["broker_displays"] = {row["display"]: broker for row, broker in zip(
        sorted(value["displays"].values(), key=lambda item: item["display"]),
        value["status"]["snapshot"]["display_incarnations"])}
    tasks = []
    for component, record_value in value["records"].items():
        if record_value["display"] == 0:
            continue
        broker = value["broker_displays"][record_value["display"]]
        tasks.append({"token": 5000 + record_value["task"], "display_token": broker["token"],
            "minimum_width": 0, "minimum_height": 0, "resizable": True,
            "visible": True, "input_enabled": True, "z_order": 0,
            "title": audit.TASK_TITLES[component], "package_name": audit.FIXTURE,
            "bounds": [record_value["left"], record_value["top"],
                       record_value["right"], record_value["bottom"]]})
    tasks.sort(key=lambda row: row["token"])
    for index, task in enumerate(tasks): task["z_order"] = index
    value["status"]["snapshot"]["tasks"] = tasks


def exact_window_input(value, component):
    row = value["records"][component]
    full = component.replace("/.", "/" + audit.FIXTURE + ".")
    token = "%07x" % (0xabc0000 + row["task"])
    value["raw"]["windows"] += ("Window #0 Window{%s u0 %s}:\n"
        "  mDisplayId=%d taskId=%d mOwnerUid=%d mHasSurface=true HAS_DRAWN\n"
        "  mActivityRecord=ActivityRecord{%s u0 %s t%d}\n"
        "  isOnScreen=true isVisible=true\n" %
        (token, full, row["display"], row["task"], UIDS[audit.FIXTURE],
         value["identities"][component]["activity_record"], component, row["task"]))
    value["raw"]["input"] += ("1: name=%s %s, displayId=%d, ownerUid=%d, inputConfig=NONE,\n" %
        (token, full, row["display"], UIDS[audit.FIXTURE]))


def bind_frame_region(frame, component, row):
    bounds = [row[name] for name in ("left", "top", "right", "bottom")]
    area = (bounds[2] - bounds[0]) * (bounds[3] - bounds[1])
    counts = {color: max(100, area // 3) for color in audit.FIXTURE_COLORS[component]}
    band_areas = {color: max(1, area // len(counts)) for color in counts}
    frame["known_colors"].update(counts)
    frame["region_known_colors"][component] = {
        "bounds": bounds, "area": area, "known_colors": counts,
        "band_known_colors": copy.deepcopy(counts), "band_areas": band_areas}


def build_semantics():
    values = {name: stage(name) for name in audit.STAGES}
    adb_shell = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell"]
    trace = [{"argv": ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "emu",
                       "multidisplay", "add", str(slot), *map(str, audit.DISPLAY_SPECS[slot]),
                       "132165"], "returncode": 0, "output": "OK"}
             for slot in (1, 2, 3)]
    rows_per_stage = 6
    for index, name in enumerate(audit.STAGES):
        values[name]["trace_start"] = 3 + index * rows_per_stage
        values[name]["trace_end"] = 3 + index * rows_per_stage + rows_per_stage
        trace.extend({"argv": ["docker", "exec", "c", "true", name, str(offset)],
                      "returncode": 0} for offset in range(rows_per_stage))

    def row(name, offset=3):
        return trace[3 + audit.STAGES.index(name) * rows_per_stage + offset]

    def reset_frames(value):
        value["frames"] = {0: {"sha256": "phone-" + value["name"],
                                "pixels_sha256": "phone-" + value["name"],
                                "known_colors": {}, "region_known_colors": {}},
            **{item["slot"]: {"sha256": "%s-%d" % (value["name"], item["slot"]),
                               "pixels_sha256": "%s-%d" % (value["name"], item["slot"]),
                               "known_colors": {}, "region_known_colors": {}}
               for item in value["displays"].values()}}

    def bind_selection(name, component):
        xml = card(audit.RECENTS_LABELS[component])
        values[name]["raw"]["selection"] = xml
        point = audit.recents_card(xml, audit.RECENTS_LABELS[component])[0]
        row(name, 2)["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                               "tap", *map(str, point)]

    def bind_focus(name, slot):
        display_id = slot + 1
        width, height, _ = audit.DISPLAY_SPECS[slot]
        row(name, 0)["argv"] = adb_shell + ["input", "mouse", "-d", str(display_id),
                                        "tap", str(width // 2), str(height // 2)]
        row(name, 1).update(argv=["docker", "exec", "c", "adb", "-s", audit.SERIAL,
                                  "shell", "dumpsys", "window", "windows"],
                            output="  mTopFocusedDisplayId=%d\n" % display_id)

    baseline = values["baseline"]
    for slot, component, task in (
            (1, audit.FIXTURE + "/.OneActivity", 8),
            (2, audit.FIXTURE + "/.TwoActivity", 9)):
        add_task(baseline, component, task, slot + 1)
        exact_window_input(baseline, component)
        bind_frame_region(baseline["frames"][slot], component,
                          baseline["records"][component])

    component = audit.COMPONENTS["cancel"]
    for name in ("cancel_menu", "cancelled"):
        add_task(values[name], component, 11)
    values["cancel_menu"]["raw"]["hierarchy"] = menu()
    bind_selection("cancel_menu", component)
    values["cancelled"]["raw"]["hierarchy"] = "<hierarchy/>"
    row("cancelled")["argv"] = adb_shell + ["input", "keyboard", "-d", "0",
                                                "keyevent", "KEYCODE_BACK"]

    component = audit.COMPONENTS["removed"]
    add_task(values["task_remove_card"], component, 12)
    exact_window_input(values["task_remove_card"], component)
    values["task_remove_card"]["raw"]["hierarchy"] = card(audit.RECENTS_LABELS[component])
    row("task_remove_card", 2)["argv"] = adb_shell + list(audit.LOG_CLEAR)
    row("task_remove_card")["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
        "swipe", "540", "1119", "540", "120", "500"]
    values["task_removed"]["raw"]["log"] = "I wm_task_removed: [12,removeTask]\n"

    for slot in (1, 2, 3):
        component = audit.COMPONENTS["transfer_%d" % slot]
        before, after = values["transfer_%d_menu" % slot], values["transfer_%d_done" % slot]
        add_task(before, component, 20 + slot)
        add_task(after, component, 20 + slot, slot + 1)
        # Moving a task preserves all opaque identities.
        after["records"][component]["instance"] = before["records"][component]["instance"]
        after["identities"][component] = copy.deepcopy(before["identities"][component])
        before["raw"]["hierarchy"] = menu()
        bind_selection("transfer_%d_menu" % slot, component)
        bind_focus("transfer_%d_menu" % slot, slot)
        point = audit.launcher_control(before["raw"]["hierarchy"], "Send to Wonad")
        row("transfer_%d_menu" % slot, 4)["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                                            "tap", *map(str, point)]
        row("transfer_%d_menu" % slot, 3)["argv"] = adb_shell + list(audit.LOG_CLEAR)
        # Only the destination framebuffer changes.
        after["frames"] = copy.deepcopy(before["frames"])
        after["frames"][slot]["sha256"] = "changed-%d" % slot
        after["frames"][slot]["pixels_sha256"] = "changed-pixels-%d" % slot
        bind_frame_region(after["frames"][slot], component,
                          after["records"][component])
        after["raw"]["log"] = "I wm_task_moved: [%d,9,%d,1,0]\n" % (
            after["records"][component]["task"], after["records"][component]["display"])
        exact_window_input(after, component)

    component = audit.COMPONENTS["selected_removed"]
    selected, detached, rejected = (values[name] for name in
        ("selected_display_menu", "selected_display_removed", "selected_display_rejected"))
    for item in (selected, detached, rejected):
        add_task(item, component, 31)
        item["records"][component]["instance"] = selected["records"][component]["instance"]
        item["identities"][component] = copy.deepcopy(selected["identities"][component])
        item["raw"]["hierarchy"] = menu()
    detached["displays"] = rejected["displays"] = {2: display(2, 1), 4: display(4, 3)}
    detached["shells"] = rejected["shells"] = {2: shell(2, 1), 4: shell(4, 3)}
    detached["homes"] = rejected["homes"] = {2: home(2, 1), 4: home(4, 3)}
    reset_frames(detached)
    rejected["frames"] = copy.deepcopy(detached["frames"])
    rejected["raw"]["hierarchy"] = "<hierarchy/>"
    bind_selection("selected_display_menu", component)
    bind_focus("selected_display_menu", 2)
    row("selected_display_removed", 0).update(
        argv=["docker", "exec", "c", "adb", "-s", audit.SERIAL, "emu", "multidisplay", "del", "2"],
        output="OK")
    point = audit.launcher_control(selected["raw"]["hierarchy"], "Send to Wonad")
    row("selected_display_rejected")["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                                          "tap", *map(str, point)]
    row("selected_display_rejected", 2)["argv"] = adb_shell + list(audit.LOG_CLEAR)

    component = audit.COMPONENTS["same_slot"]
    old, absent, readded, rejected = (values[name] for name in
        ("same_slot_menu", "same_slot_removed", "same_slot_readded", "same_slot_rejected"))
    for item in (old, absent, readded, rejected):
        add_task(item, component, 32)
        item["records"][component]["instance"] = old["records"][component]["instance"]
        item["identities"][component] = copy.deepcopy(old["identities"][component])
        item["raw"]["hierarchy"] = menu()
    # Slot 2 was removed by the preceding scenario.  Slot 3 is now unplugged.
    old["displays"] = {2: display(2, 1), 4: display(4, 3)}
    old["shells"] = {2: shell(2, 1), 4: shell(4, 3)}
    old["homes"] = {2: home(2, 1), 4: home(4, 3)}
    reset_frames(old)
    absent["displays"] = {2: display(2, 1)}
    absent["shells"] = {2: shell(2, 1)}
    absent["homes"] = {2: home(2, 1)}
    reset_frames(absent)
    new_display = display(5, 3)
    for item in (readded, rejected):
        item["displays"] = {2: display(2, 1), 5: new_display}
        item["shells"] = {2: shell(2, 1), 5: shell(5, 3)}
        item["homes"] = {2: home(2, 1), 5: home(5, 3, 9)}
        reset_frames(item)
    rejected["frames"] = copy.deepcopy(readded["frames"])
    rejected["raw"]["hierarchy"] = "<hierarchy/>"

    # No implicit reset is permitted after the same-slot replacement.  Every
    # later capture observes the surviving slot 1 and the new slot-3
    # incarnation until the runtime is deliberately stopped.
    for name in ("screenshot_menu", "screenshot_activated", "split_menu",
                 "split_select", "split_activated", "unavailable"):
        item = values[name]
        item["displays"] = {2: display(2, 1), 5: copy.deepcopy(new_display)}
        item["shells"] = {2: shell(2, 1), 5: shell(5, 3)}
        item["homes"] = {2: home(2, 1), 5: home(5, 3, 9)}
        reset_frames(item)
    bind_selection("same_slot_menu", component)
    bind_focus("same_slot_menu", 3)
    row("same_slot_removed", 0).update(
        argv=["docker", "exec", "c", "adb", "-s", audit.SERIAL, "emu", "multidisplay", "del", "3"],
        output="OK")
    row("same_slot_readded", 0).update(
        argv=["docker", "exec", "c", "adb", "-s", audit.SERIAL, "emu", "multidisplay", "add", "3",
              *map(str, audit.DISPLAY_SPECS[3]), "132165"], output="OK")
    point = audit.launcher_control(old["raw"]["hierarchy"], "Send to Wonad")
    row("same_slot_rejected")["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                                "tap", *map(str, point)]
    row("same_slot_rejected", 2)["argv"] = adb_shell + list(audit.LOG_CLEAR)

    component = audit.COMPONENTS["screenshot"]
    before, after = values["screenshot_menu"], values["screenshot_activated"]
    for item in (before, after):
        add_task(item, component, 33)
        item["records"][component]["instance"] = before["records"][component]["instance"]
        item["identities"][component] = copy.deepcopy(before["identities"][component])
    before["raw"]["hierarchy"] = menu()
    bind_selection("screenshot_menu", component)
    after["raw"].update(hierarchy='<hierarchy><node package="com.android.systemui" text="Screenshot preview" /></hierarchy>',
                         windows=("Window #0 Window{abc u0 ScreenshotController}:\n"
                                  "  mDisplayId=0 mOwnerUid=%d mHasSurface=true HAS_DRAWN\n"
                                  "  isOnScreen=true isVisible=true\n" %
                                  UIDS[audit.SYSTEMUI]),
                         log="I ScreenshotController: screenshot_saved request complete")
    after["frames"][0]["sha256"] = "screenshot-changed"
    after["frames"][0]["pixels_sha256"] = "screenshot-pixels-changed"
    point = audit.launcher_control(before["raw"]["hierarchy"], "Screenshot")
    row("screenshot_menu", 4)["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                               "tap", *map(str, point)]
    row("screenshot_menu", 3)["argv"] = adb_shell + list(audit.LOG_CLEAR)

    primary, secondary = audit.COMPONENTS["split_primary"], audit.COMPONENTS["split_secondary"]
    split_menu, split_select, split_after = (values[name] for name in
        ("split_menu", "split_select", "split_activated"))
    add_task(split_menu, primary, 34)
    add_task(split_select, primary, 34); add_task(split_select, secondary, 35)
    add_task(split_after, primary, 34); add_task(split_after, secondary, 35)
    for component in (primary, secondary):
        origin = split_menu if component == primary else split_select
        for item in (split_select, split_after):
            if component in item["records"]:
                item["records"][component]["instance"] = origin["records"][component]["instance"]
                item["identities"][component] = copy.deepcopy(origin["identities"][component])
    split_menu["raw"]["hierarchy"] = menu()
    bind_selection("split_menu", primary)
    split_select["raw"]["hierarchy"] = card(audit.RECENTS_LABELS[secondary])
    split_after["raw"]["activities"] = (
        "  * Task{aa00001 #34 U=0 windowingMode=multi-window}\n"
        "  * Task{aa00002 #35 U=0 windowingMode=multi-window}\n")
    split_after["records"][primary].update(left=0, top=0, right=1080, bottom=1180)
    split_after["records"][secondary].update(left=0, top=1220, right=1080, bottom=2400)
    exact_window_input(split_after, primary)
    exact_window_input(split_after, secondary)
    split_after["raw"]["log"] = ("I wm_task_moved: [34,4,0,1,0]\n"
                                    "I wm_task_moved: [35,6,0,1,0]\n")
    split_after["frames"][0]["sha256"] = "split-changed"
    split_after["frames"][0]["pixels_sha256"] = "split-pixels-changed"
    for component in (primary, secondary):
        bind_frame_region(split_after["frames"][0], component,
                          split_after["records"][component])
    point = audit.launcher_control(split_menu["raw"]["hierarchy"], "Split screen")
    row("split_menu", 4)["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                          "tap", *map(str, point)]
    row("split_menu", 3)["argv"] = adb_shell + list(audit.LOG_CLEAR)
    point = audit.recents_card(split_select["raw"]["hierarchy"], audit.RECENTS_LABELS[secondary], chip=False)[0]
    row("split_select")["argv"] = adb_shell + ["input", "touchscreen", "-d", "0",
                                            "tap", *map(str, point)]

    unavailable = values["unavailable"]
    unavailable["shells"] = {}
    component = audit.COMPONENTS["unavailable"]
    add_task(unavailable, component, 33)
    unavailable["records"][component]["instance"] = before["records"][component]["instance"]
    unavailable["identities"][component] = copy.deepcopy(before["identities"][component])
    unavailable["raw"]["hierarchy"] = menu(False)
    bind_selection("unavailable", component)

    # Construct one monotone runtime ledger and persistent broker task-token
    # catalogue.  Phone-only fixture records never enter the catalogue.
    task_ledger = {}
    topology = 20
    for ordinal, name in enumerate(audit.STAGES):
        value = values[name]
        if name in {"selected_display_removed", "same_slot_removed", "same_slot_readded"}:
            topology += 1
        state = "stopped" if name == "unavailable" else (
            "running" if name in audit.BLOCKED_STAGES else "ready")
        value["status"] = session_status(value["displays"], state, revision=100 + ordinal,
                                         topology=topology, updated=200 + ordinal)
        value["broker_displays"] = {item["display"]: broker for item, broker in zip(
            sorted(value["displays"].values(), key=lambda entry: entry["display"]),
            value["status"]["snapshot"]["display_incarnations"])}
        live_tokens = {item["token"] for item in value["broker_displays"].values()}
        task_ledger = {token: item for token, item in task_ledger.items()
                       if item["display_token"] in live_tokens}
        if name == "baseline":
            for moved_component in (audit.FIXTURE + "/.OneActivity",
                                    audit.FIXTURE + "/.TwoActivity"):
                moved = value["records"][moved_component]
                broker = value["broker_displays"][moved["display"]]
                token = 5000 + moved["task"]
                task_ledger[token] = {"token": token, "display_token": broker["token"],
                    "minimum_width": 0, "minimum_height": 0, "resizable": True,
                    "visible": True, "input_enabled": True, "z_order": 0,
                    "title": audit.TASK_TITLES[moved_component], "package_name": audit.FIXTURE,
                    "bounds": [moved[key] for key in ("left", "top", "right", "bottom")]}
        if name in {"transfer_1_done", "transfer_2_done", "transfer_3_done"}:
            transfer = int(name.split("_")[1])
            moved_component = audit.COMPONENTS["transfer_%d" % transfer]
            moved = value["records"][moved_component]
            broker = value["broker_displays"][moved["display"]]
            # Existing windows on that monitor are retiled, so their broker
            # bounds cannot alias the newly transferred exact Activity bounds.
            for existing in task_ledger.values():
                if existing["display_token"] == broker["token"]:
                    existing["bounds"] = [1000, 0, 1800, 1000]
            token = 5000 + moved["task"]
            task_ledger[token] = {"token": token, "display_token": broker["token"],
                "minimum_width": 0, "minimum_height": 0, "resizable": True,
                "visible": True, "input_enabled": True, "z_order": 0,
                "title": audit.TASK_TITLES[moved_component], "package_name": audit.FIXTURE,
                "bounds": [moved[key] for key in ("left", "top", "right", "bottom")]}
        tasks = [copy.deepcopy(item) for _, item in sorted(task_ledger.items())]
        for index, item in enumerate(tasks): item["z_order"] = index
        value["status"]["snapshot"]["tasks"] = tasks

    # Materialize every long-lived external native task in every capture, as
    # the real dumpsys streams do.  Follow the broker's legitimate tiling
    # bounds while preserving the original Task/ActivityRecord identities.
    for component, (first, last) in audit.EXTERNAL_SURVIVOR_LIFETIMES.items():
        anchor = values[first]
        anchor_record = copy.deepcopy(anchor["records"][component])
        anchor_identity = copy.deepcopy(anchor["identities"][component])
        for name in audit.STAGES[audit.STAGES.index(first):audit.STAGES.index(last) + 1]:
            value = values[name]
            current = copy.deepcopy(anchor_record)
            broker_rows = [row for row in value["status"]["snapshot"]["tasks"]
                           if row["token"] == 5000 + current["task"]]
            if len(broker_rows) == 1:
                current.update(dict(zip(("left", "top", "right", "bottom"),
                                        broker_rows[0]["bounds"])))
            value["records"][component] = current
            value["membership"][current["task"]] = current["display"]
            value["identities"][component] = copy.deepcopy(anchor_identity)
            full = component.replace("/.", "/" + audit.FIXTURE + ".")
            if full not in value["raw"]["windows"]:
                exact_window_input(value, component)
            display_row = value["displays"][current["display"]]
            bind_frame_region(value["frames"][display_row["slot"]], component, current)
    return values, trace


class RecentsSemanticTests(unittest.TestCase):
    def test_complete_semantic_model_passes(self):
        stages, trace = build_semantics()
        self.assertTrue(audit.audit_semantics(stages, trace, UIDS))

    def test_task_or_activity_identity_replacement_fails(self):
        for field in ("task", "instance", "binder", "pid", "task_object", "activity_record"):
            stages, trace = build_semantics()
            component = audit.COMPONENTS["transfer_1"]
            target = stages["transfer_1_done"]["records" if field in ("task", "instance") else "identities"][component]
            target[field] = 999 if field in ("task", "pid") else "recycled"
            with self.subTest(field=field), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_removed_destination_never_falls_back_to_survivor(self):
        stages, trace = build_semantics()
        component = audit.COMPONENTS["selected_removed"]
        stages["selected_display_rejected"]["records"][component]["display"] = 2
        stages["selected_display_rejected"]["membership"][31] = 2
        with self.assertRaisesRegex(audit.EvidenceError, "wrong Android display|failed open"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_same_slot_requires_a_new_native_incarnation(self):
        stages, trace = build_semantics()
        old = stages["same_slot_menu"]["homes"][4]
        recycled = copy.deepcopy(old); recycled.update(display=5, slot=3)
        for name in ("same_slot_readded", "same_slot_rejected", "screenshot_menu",
                     "screenshot_activated", "split_menu", "split_select",
                     "split_activated", "unavailable"):
            stages[name]["homes"][5] = copy.deepcopy(recycled)
        with self.assertRaisesRegex(audit.EvidenceError, "reused"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_new_logical_display_id_still_requires_native_home(self):
        stages, trace = build_semantics()
        stages["same_slot_readded"]["homes"] = {2: home(2, 1)}
        with self.assertRaisesRegex(audit.EvidenceError, "Home topology"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_screenshot_label_or_tap_without_activation_never_passes(self):
        for mutation in ("log", "window", "frame", "tap"):
            stages, trace = build_semantics()
            after = stages["screenshot_activated"]
            if mutation == "log": after["raw"]["log"] = "Screenshot label only"
            if mutation == "window": after["raw"]["windows"] = "ordinary window"
            if mutation == "frame": after["frames"][0] = copy.deepcopy(stages["screenshot_menu"]["frames"][0])
            if mutation == "tap": trace[stages["screenshot_menu"]["trace_start"] + 3]["argv"][-1] = "999"
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_split_label_without_two_exact_multiwindow_tasks_never_passes(self):
        for mutation in ("second_identity", "multiwindow", "log", "frame", "second_tap"):
            stages, trace = build_semantics()
            after = stages["split_activated"]
            secondary = audit.COMPONENTS["split_secondary"]
            if mutation == "second_identity": after["identities"][secondary]["activity_record"] = "recycled"
            if mutation == "multiwindow": after["raw"]["activities"] = after["raw"]["activities"].replace("multi-window", "fullscreen")
            if mutation == "log": after["raw"]["log"] = "Split screen label only"
            if mutation == "frame": after["frames"][0] = copy.deepcopy(stages["split_menu"]["frames"][0])
            if mutation == "second_tap": trace[stages["split_select"]["trace_start"] + 3]["argv"][-1] = "999"
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_unavailable_session_cannot_retain_shell_or_send_action(self):
        for mutation in ("shell", "action", "running"):
            stages, trace = build_semantics(); value = stages["unavailable"]
            if mutation == "shell": value["shells"] = {2: shell(2, 1)}
            if mutation == "action": value["raw"]["hierarchy"] = menu(True)
            if mutation == "running": value["status"]["state"] = "running"
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_back_and_task_removal_need_ordered_real_input(self):
        for stage_name in ("cancelled", "task_remove_card"):
            stages, trace = build_semantics()
            trace[stages[stage_name]["trace_start"] + 3]["argv"] = ["docker", "exec", "c", "true"]
            with self.subTest(stage=stage_name), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_menu_label_without_selected_exact_card_never_passes(self):
        for mutation in ("missing_card", "wrong_chip_tap"):
            stages, trace = build_semantics()
            value = stages["transfer_1_menu"]
            if mutation == "missing_card":
                value["raw"]["selection"] = None
            else:
                expected = audit.recents_card(value["raw"]["selection"],
                    audit.RECENTS_LABELS[audit.COMPONENTS["transfer_1"]])[0]
                rows = [row for row in trace[value["trace_start"]:value["trace_end"]]
                        if row["argv"][-len(expected):] == list(map(str, expected))]
                self.assertEqual(1, len(rows))
                rows[0]["argv"][-1] = "999"
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_destination_requires_focus_and_hotplug_commands(self):
        mutations = (
            ("transfer_2_menu", 0),
            ("selected_display_removed", 0),
            ("same_slot_readded", 0),
        )
        for name, offset in mutations:
            stages, trace = build_semantics()
            trace[stages[name]["trace_start"] + offset]["argv"] = ["docker", "exec", "c", "true"]
            with self.subTest(stage=name), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_arbitrary_topology_jump_between_non_hotplug_stages_fails(self):
        stages, trace = build_semantics()
        value = stages["screenshot_menu"]
        value["displays"] = {2: display(2, 1), 3: display(3, 2), 4: display(4, 3)}
        value["shells"] = {2: shell(2, 1), 3: shell(3, 2), 4: shell(4, 3)}
        value["homes"] = {2: home(2, 1), 3: home(3, 2), 4: home(4, 3)}
        old_status = value["status"]
        value["status"] = session_status(value["displays"], "running",
            revision=old_status["snapshot"]["revision"],
            topology=old_status["snapshot"]["topology_revision"],
            updated=old_status["updated_elapsed_ms"])
        value["status"]["snapshot"]["tasks"] = copy.deepcopy(old_status["snapshot"]["tasks"])
        value["broker_displays"] = {row["display_id"]: copy.deepcopy(row)
            for row in value["status"]["snapshot"]["display_incarnations"]}
        with self.assertRaisesRegex(audit.EvidenceError, "topology|incarnation"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_broker_ghost_and_stale_row_mutation_fail(self):
        stages, trace = build_semantics()
        stages["cancel_menu"]["status"]["snapshot"]["tasks"] = [{
            "token": 9999, "display_token": 1002, "minimum_width": 0,
            "minimum_height": 0, "resizable": True, "visible": True,
            "input_enabled": True, "z_order": 0, "title": audit.FIXTURE,
            "package_name": audit.FIXTURE, "bounds": [0, 0, 900, 1000]}]
        with self.assertRaisesRegex(audit.EvidenceError, "catalogue"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_broker_task_must_be_visible_and_input_enabled(self):
        stages, _trace = build_semantics()
        component = audit.COMPONENTS["transfer_1"]
        value = stages["transfer_1_done"]
        task = value["records"][component]["task"]
        rows = [row for row in value["status"]["snapshot"]["tasks"]
                if row["token"] == 5000 + task]
        self.assertEqual(1, len(rows))
        self.assertIs(rows[0], audit.runtime_task(value, component))
        rows[0]["visible"] = rows[0]["input_enabled"] = False
        with self.assertRaisesRegex(audit.EvidenceError, "exact task"):
            audit.runtime_task(value, component)

    def test_prior_external_task_needs_native_window_input_and_pixels_at_later_stages(self):
        component = audit.COMPONENTS["transfer_1"]
        mutations = ("identity", "window", "pixels")
        for mutation in mutations:
            stages, trace = build_semantics()
            target = stages["selected_display_rejected"]
            if mutation == "identity":
                target["identities"][component]["activity_record"] = "restarted"
            elif mutation == "window":
                full = component.replace("/.", "/" + audit.FIXTURE + ".")
                target["raw"]["windows"] = target["raw"]["windows"].replace(full, "missing", 1)
            else:
                target["frames"][1]["region_known_colors"].pop(component)
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

        stages, trace = build_semantics()
        tasks = stages["selected_display_rejected"]["status"]["snapshot"]["tasks"]
        self.assertTrue(tasks)
        tasks[0]["bounds"] = [1, 1, 901, 1001]
        with self.assertRaisesRegex(audit.EvidenceError, "catalogue"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_external_component_cannot_swap_opaque_broker_tokens(self):
        stages, trace = build_semantics()
        target = stages["transfer_2_menu"]["status"]["snapshot"]["tasks"]
        tokens = {row["token"]: row for row in target}
        first = 5000 + stages["baseline"]["records"][audit.FIXTURE + "/.OneActivity"]["task"]
        second_component = audit.COMPONENTS["transfer_1"]
        second = 5000 + stages["transfer_1_done"]["records"][second_component]["task"]
        self.assertEqual(tokens[first]["display_token"], tokens[second]["display_token"])
        # Preserve each exact component's title/geometry while substituting
        # only its opaque current token. The independent lifetime check must
        # still catch this, even after title matching became stricter.
        tokens[first]["token"], tokens[second]["token"] = second, first
        target.sort(key=lambda row: row["token"])
        with self.assertRaisesRegex(audit.EvidenceError, "broker-task lifetime"):
            audit.audit_external_survivors(stages, UIDS[audit.FIXTURE])
        # The complete auditor additionally detects the earlier per-token
        # catalogue chronology violation; neither guard is relaxed.
        with self.assertRaisesRegex(audit.EvidenceError, "catalogue changed"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_blocked_and_settled_runtime_states_cannot_be_swapped(self):
        stages, trace = build_semantics()
        blocked = stages["cancel_menu"]["status"]
        blocked.update(state="ready", phase="ready",
                       runtime_readiness={"ready": True, "session_open": True,
                                          "reopen_required": False})
        blocked["snapshot"]["interaction_blocked"] = False
        with self.assertRaisesRegex(audit.EvidenceError, "Protected phone UI"):
            audit.audit_semantics(stages, trace, UIDS)

        stages, trace = build_semantics()
        settled = stages["transfer_1_done"]["status"]
        settled.update(state="running", phase="syncing-shells",
                       runtime_readiness={"ready": False, "session_open": True,
                                          "reopen_required": False})
        settled["snapshot"]["interaction_blocked"] = True
        with self.assertRaisesRegex(audit.EvidenceError, "Settled capture"):
            audit.audit_semantics(stages, trace, UIDS)

    def test_runtime_error_or_one_shot_coverage_claim_fails(self):
        for mutation in ("control_error", "one_shot"):
            stages, trace = build_semantics()
            status = stages["baseline"]["status"]
            if mutation == "control_error":
                status["control_error"] = "rejected stale nonce"
            else:
                status["one_shot_api_coverage"] = {"mode": "full", "status": "passed"}
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.audit_semantics(stages, trace, UIDS)

    def test_pixels_and_split_geometry_cannot_be_label_only(self):
        stages, trace = build_semantics()
        stages["transfer_1_done"]["frames"][1]["region_known_colors"] = {}
        with self.assertRaisesRegex(audit.EvidenceError, "palette|pixels"):
            audit.audit_semantics(stages, trace, UIDS)

        stages, trace = build_semantics()
        component = audit.COMPONENTS["split_secondary"]
        stages["split_activated"]["records"][component].update(top=2300, bottom=2400)
        bind_frame_region(stages["split_activated"]["frames"][0], component,
                          stages["split_activated"]["records"][component])
        with self.assertRaisesRegex(audit.EvidenceError, "clipped|tiny|outside"):
            audit.audit_semantics(stages, trace, UIDS)


class RecentsRuntimeTraceHelperTests(unittest.TestCase):
    def setUp(self):
        self.run = "1" * 32
        self.service = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell",
                        "dumpsys", "activity", "service", audit.APP + "/.ConformanceService"]

    def control(self, nonce, phase="checkpoint", run=None):
        run = run or self.run
        return {"argv": self.service + ["runtime-command", run, nonce, phase],
                "returncode": 0,
                "output": "WONAD_CONFORMANCE_CONTROL accepted %s %s %s\n" %
                          (run, nonce, phase)}

    def test_producer_waits_for_a_visible_input_enabled_broker_task(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint",
                Path(temporary), 30)
            component = audit.COMPONENTS["transfer_1"]
            record_value = record(component, 21, 2)
            status = session_status({2: display(2, 1)})
            broker = status["snapshot"]["display_incarnations"][0]
            task = {"token": 5021, "display_token": broker["token"],
                "minimum_width": 0, "minimum_height": 0, "resizable": True,
                "visible": True, "input_enabled": True, "z_order": 0,
                "title": audit.TASK_TITLES[component], "package_name": audit.FIXTURE,
                "bounds": [record_value[name] for name in ("left", "top", "right", "bottom")]}
            status["snapshot"]["tasks"] = [task]
            value.runtime_topology_ready = lambda: status
            value.fixture = lambda: {component: record_value}
            self.assertIs(status, value.runtime_task_ready(component, 2))
            task["visible"] = task["input_enabled"] = False
            self.assertFalse(value.runtime_task_ready(component, 2))

    def test_control_inventory_rejects_foreign_copy_reopen_and_extra_args(self):
        good = [self.control("2" * 32), self.control("3" * 32, "stop")]
        self.assertEqual(2, len(audit.runtime_control_rows(good, self.service, self.run)))
        mutations = [
            [self.control("2" * 32, run="4" * 32)],
            [self.control("2" * 32, phase="copy-observed")],
            [self.control("2" * 32, phase="reopen")],
        ]
        extra = self.control("2" * 32); extra["argv"].append("extra"); mutations.append([extra])
        for rows in mutations:
            with self.subTest(argv=rows[0]["argv"]), self.assertRaises(audit.EvidenceError):
                audit.runtime_control_rows(rows, self.service, self.run)

    def test_nonce_marker_status_binding_rejects_replay(self):
        nonce = "2" * 32
        status = session_status({2: display(2, 1)})
        status["handshake"] = {"nonce": nonce, "phase": "checkpoint", "result": "accepted"}
        row = self.control(nonce)
        self.assertEqual(nonce, audit.bind_runtime_control(row, self.run, "checkpoint", status, set()))
        with self.assertRaisesRegex(audit.EvidenceError, "replayed"):
            audit.bind_runtime_control(row, self.run, "checkpoint", status, {nonce})

    def test_accepted_ready_poll_rejects_blocked_unshelled_or_error_state(self):
        nonce = "2" * 32
        value = session_status({2: display(2, 1)})
        value["handshake"] = {"nonce": nonce, "phase": "checkpoint", "result": "accepted"}
        self.assertTrue(audit.accepted_ready_observation(value, self.run, nonce,
                                                         "checkpoint", {2}))
        for mutation in ("blocked", "unshelled", "error", "foreign"):
            changed = copy.deepcopy(value)
            if mutation == "blocked": changed["snapshot"]["interaction_blocked"] = True
            if mutation == "unshelled": changed["snapshot"]["display_incarnations"][0]["shell_generation"] = 0
            if mutation == "error": changed["control_error"] = "bad nonce"
            if mutation == "foreign": changed["run"] = "9" * 32
            with self.subTest(mutation=mutation):
                self.assertFalse(audit.accepted_ready_observation(
                    changed, self.run, nonce, "checkpoint", {2}))

    def test_stop_must_be_last_reviewed_control_before_finish(self):
        checkpoint = self.control("2" * 32)
        stop = self.control("3" * 32, "stop")
        self.assertTrue(audit.validate_control_completion(
            [(1, checkpoint), (2, stop)], {1, 2}, 3))
        with self.assertRaisesRegex(audit.EvidenceError, "stop ordering"):
            audit.validate_control_completion([(1, stop), (2, checkpoint)], {1, 2}, 3)

    def test_instrumentation_terminal_output_must_be_exact_success(self):
        good = "\n".join((
            "INSTRUMENTATION_RESULT: run=" + self.run,
            "INSTRUMENTATION_RESULT: mode=runtime",
            "INSTRUMENTATION_RESULT: api=3",
            "INSTRUMENTATION_RESULT: runtime=stopped",
            "INSTRUMENTATION_CODE: -1", ""))
        self.assertTrue(audit.instrumentation_success(good, self.run))
        for changed in (good.replace("runtime=stopped", "runtime=failed"),
                        good.replace("INSTRUMENTATION_CODE: -1", "INSTRUMENTATION_CODE: 0"),
                        good + "INSTRUMENTATION_FAILED: Process crashed\n"):
            with self.assertRaises(audit.EvidenceError):
                audit.instrumentation_success(changed, self.run)

    def test_hierarchy_read_requires_fresh_dump_and_cleanup(self):
        remote = "/data/local/tmp/wonad-phase1-recents-" + "a" * 16 + ".xml"
        shell = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell"]
        cat = {"argv": shell[:6] + ["exec-out", "cat", remote], "returncode": 0,
               "output": "<hierarchy/>"}
        trace = [
            {"argv": shell + ["uiautomator", "dump", remote], "returncode": 0},
            cat,
            {"argv": shell + ["rm", "--", remote], "returncode": 0},
        ]
        self.assertEqual(1, audit.validate_hierarchy_lifecycle(trace, cat, "c", remote))
        trace[0]["argv"][-1] += ".stale"
        with self.assertRaises(audit.EvidenceError):
            audit.validate_hierarchy_lifecycle(trace, cat, "c", remote)

    def test_complete_input_inventory_rejects_an_extra_valid_action(self):
        shell = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell"]
        trace = [
            {"argv": shell + ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"],
             "returncode": 0},
            {"argv": shell + ["input", "touchscreen", "-d", "0", "swipe",
                               "900", "1200", "180", "1200", "350"], "returncode": 0},
            {"argv": shell + ["input", "touchscreen", "-d", "0", "tap", "300", "485"],
             "returncode": 0},
        ]
        self.assertTrue(audit.require_consumed_input_inventory(trace, shell, {0, 1, 2}))
        trace.append({"argv": shell + ["input", "keyboard", "-d", "0", "keyevent",
                                              "KEYCODE_HOME"], "returncode": 0})
        with self.assertRaisesRegex(audit.EvidenceError, "Unconsumed"):
            audit.require_consumed_input_inventory(trace, shell, {0, 1, 2})

    def test_frame_copy_and_directory_commands_are_outward_and_exact(self):
        container = "a" * 64
        remote = "/state/phase1-recents-" + "b" * 32 + "-" + "c" * 8 + "-1"
        good = (
            ["docker", "exec", container, "mkdir", "-m", "700", "--", remote],
            ["docker", "exec", container, "find", remote, "-maxdepth", "1", "-type", "f",
             "-name", "*.png", "-printf", "%f\\n"],
            ["docker", "exec", container, "rm", "-rf", "--", remote],
            ["docker", "cp", container + ":" + remote + "/screen.png", "/tmp/screen.png"],
        )
        for argv in good:
            self.assertTrue(audit.reviewed_command(argv))
        for argv in (
            good[1][:-2] + ["-exec", "cp", "{}", remote + "/screen.png", ";"],
            ["docker", "cp", "/tmp/crafted.png", container + ":" + remote + "/screen.png"],
        ):
            with self.assertRaises(audit.EvidenceError):
                audit.reviewed_command(argv)

    def test_log_inventory_rejects_a_post_action_clear(self):
        shell = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell"]
        names = ("task_remove_card", "transfer_1_menu", "transfer_2_menu",
                 "transfer_3_menu", "selected_display_rejected", "same_slot_rejected",
                 "screenshot_menu", "split_menu")
        trace, stages = [], {}
        for name in names:
            start = len(trace)
            trace.append({"argv": shell + list(audit.LOG_CLEAR), "returncode": 0})
            stages[name] = {"trace_start": start, "trace_end": len(trace)}
        read = shell + ["logcat", "-b", "main", "-b", "events", "-d", "-v",
                        "threadtime", "-t", "4000"]
        trace.append({"argv": read, "returncode": 0, "evidence": "stage/log.txt"})
        report = {"container_id": "c", "stages": [{"files": {"log": "stage/log.txt"}}]}
        self.assertTrue(audit.validate_log_inventory(trace, report, stages))
        trace.append({"argv": shell + list(audit.LOG_CLEAR), "returncode": 0})
        with self.assertRaisesRegex(audit.EvidenceError, "Extra main-buffer clear"):
            audit.validate_log_inventory(trace, report, stages)

    def test_main_only_clear_cannot_erase_an_earlier_protected_event(self):
        self.assertEqual(("logcat", "-b", "main", "-c"), audit.LOG_CLEAR)
        container = "a" * 64
        shell = ["docker", "exec", container, "adb", "-s", audit.SERIAL, "shell"]
        self.assertTrue(audit.reviewed_command(shell + list(audit.LOG_CLEAR)))
        with self.assertRaisesRegex(audit.EvidenceError, "unreviewed log clear"):
            audit.reviewed_command(
                shell + ["logcat", "-b", "main", "-b", "events", "-c"])
        before_clear = "I am_anr: [0,1601,com.android.systemui,Input dispatch timeout]\n"
        later_cumulative_read = before_clear + "I wm_task_moved: [42,9,2,1,0]\n"
        with self.assertRaisesRegex(audit.EvidenceError, "Protected process crash/ANR"):
            audit.no_protected_failure(later_cumulative_read)

    def test_real_capture_command_grammar_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            commands = []

            def command(argv, *, timeout=60, allowed=(0,), evidence=None, binary=False):
                commands.append(list(map(str, argv)))
                if evidence is not None:
                    path = output / evidence
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    if evidence.endswith("display.txt"):
                        payload = ("  mBaseDisplayInfo=DisplayInfo{name, displayId 0, "
                            "type INTERNAL, uniqueId \"local:1\", real 1080 x 2400, "
                            "density 420 (420.0 x 420.0) dpi, state ON, }\n").encode()
                    elif evidence.endswith(".xml"):
                        payload = b"<hierarchy/>\n"
                    else:
                        payload = b"captured\n"
                    producer.write_new(path, payload)
                return b"captured" if binary else "captured"

            value.command = command
            value.runtime_command = lambda phase: None
            row = value.capture("baseline")
            self.assertEqual("baseline", row["name"])
            input_command = ["docker", "exec", "a" * 64, "adb", "-s", audit.SERIAL,
                             "shell", "dumpsys", "input"]
            self.assertEqual(1, commands.count(input_command))
            for argv in commands:
                with self.subTest(argv=argv):
                    self.assertTrue(audit.reviewed_command(argv))

    def test_stale_rejection_log_must_follow_action_home_and_checkpoint(self):
        stage_value = {"trace_start": 0, "trace_end": 4}
        trace = [
            {"kind": "action"},
            {"kind": "home"},
            {"kind": "checkpoint"},
            {"evidence": "stage/rejection-log.txt"},
        ]
        self.assertEqual(3, audit.require_stage_log_after(
            trace, stage_value, "stage/rejection-log.txt", [0, 1, 2], "stale"))
        trace[0], trace[3] = trace[3], trace[0]
        with self.assertRaisesRegex(audit.EvidenceError, "precedes"):
            audit.require_stage_log_after(
                trace, stage_value, "stage/rejection-log.txt", [1, 2, 3], "stale")


class ColdConformanceServiceTests(unittest.TestCase):
    ABSENT = ("No services match: " + audit.APP + "/.ConformanceService\n"
              "Use -h for help.")

    def test_fresh_uncreated_service_has_exact_pinned_framework_absence(self):
        for raw in (self.ABSENT, self.ABSENT + "\n"):
            with self.subTest(raw=raw):
                self.assertEqual({"schema": 1, "state": "absent", "phase": "absent"},
                                 audit.inactive_conformance_status(raw))

    def test_absence_rejects_foreign_ambiguous_truncated_and_extra_output(self):
        idle = 'WONAD_CONFORMANCE_STATUS {"schema":1,"state":"idle","phase":"idle"}\n'
        for raw in ("", self.ABSENT.splitlines()[0],
                    self.ABSENT.replace(audit.APP, "other.package"),
                    self.ABSENT + "\n" + self.ABSENT, self.ABSENT + "\nextra",
                    self.ABSENT + "\n" + idle, idle + self.ABSENT + "\n",
                    self.ABSENT + "\n\n"):
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.inactive_conformance_status(raw)

    def test_idle_remains_valid_and_active_or_duplicate_status_is_rejected(self):
        idle = 'WONAD_CONFORMANCE_STATUS {"schema":1,"state":"idle","phase":"idle"}\n'
        self.assertEqual("idle", audit.inactive_conformance_status(idle)["state"])
        active = "WONAD_CONFORMANCE_STATUS " + json.dumps(session_status({})) + "\n"
        for raw in (idle + idle, active):
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.inactive_conformance_status(raw)

    def test_failed_real_producer_preserves_rejected_raw_status_and_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            value._record({"kind": "command", "argv": ["docker", "exec", value.container,
                "adb", "-s", audit.SERIAL, "shell", "dumpsys", "activity", "service", producer.SERVICE],
                "returncode": 0, "started_monotonic_ns": 1, "ended_monotonic_ns": 2,
                "output": self.ABSENT + "\nforeign output\n"})
            result = value.seal_failure(ValueError("rejected raw prior status"))
            self.assertEqual(audit.file_ref(output / "failure.json"),
                             {key: result[key] for key in ("sha256", "bytes")})
            retained = json.loads((output / "commands.json").read_bytes())
            self.assertEqual(value.trace, retained)
            self.assertEqual(self.ABSENT + "\nforeign output\n", retained[0]["output"])
            failed = json.loads((output / "failure.json").read_bytes())
            self.assertEqual("failed_not_qualified", failed["status"])
            self.assertEqual(audit.file_ref(output / "commands.json"),
                             {key: failed["commands"][key] for key in ("sha256", "bytes")})
            self.assertFalse((output / "report.json").exists())

    def test_failure_sealing_cannot_overwrite_existing_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            (output / "commands.json").write_bytes(b"preserved unrelated bytes")
            with self.assertRaisesRegex(ValueError, "Existing failed command journal differs"):
                value.seal_failure(ValueError("failure"))
            self.assertEqual(b"preserved unrelated bytes", (output / "commands.json").read_bytes())
            self.assertFalse((output / "failure.json").exists())


class RecentsPhoneOverviewTests(unittest.TestCase):
    HOME_XML = ('<hierarchy rotation="0"><node package="com.android.launcher3" '
        'resource-id="com.android.launcher3:id/drag_layer" enabled="true" '
        'bounds="[0,0][1080,2400]">'
        '<node package="com.android.launcher3" resource-id="com.android.launcher3:id/workspace" '
        'class="android.widget.ScrollView" enabled="true" bounds="[0,0][1080,2400]"/>'
        '<node package="com.android.launcher3" '
        'resource-id="com.android.launcher3:id/accessibility_action_view" '
        'content-desc="Home" enabled="true" bounds="[0,63][1080,2337]"/>'
        '<node package="com.android.launcher3" '
        'resource-id="com.android.launcher3:id/overview_actions_view" enabled="true" '
        'bounds="[0,1889][1080,2400]"/></node></hierarchy>')
    ACTIVITIES = ("Display #0 (activities from top to bottom):\n"
        "  * Task{abc #9 type=home U=0 visible=true visibleRequested=true}\n"
        "    topResumedActivity=ActivityRecord{abc u0 " + audit.PHONE_HOME_COMPONENT + " t9}\n"
        "    * Hist  #0: ActivityRecord{abc u0 " + audit.PHONE_HOME_COMPONENT + " t9}\n"
        "      mActivityComponent=" + audit.PHONE_HOME_COMPONENT + "\n"
        "      state=RESUMED finishing=false\n      mActivityType=home\n"
        "      mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true\n"
        "      nowVisible=true lastVisibleTime=-100ms\n"
        "  ResumedActivity: ActivityRecord{abc u0 " + audit.PHONE_HOME_COMPONENT + " t9}\n")
    DISPLAYS = ("Display: mDisplayId=0 (organized)\n"
        "  mCurrentFocus=Window{def u0 " + audit.PHONE_HOME_WINDOW + "}\n"
        "  mFocusedApp=ActivityRecord{abc u0 " + audit.PHONE_HOME_COMPONENT + " t9}\n")
    WINDOWS = ("Window #0 Window{def u0 " + audit.PHONE_HOME_WINDOW + "}:\n"
        "  mDisplayId=0 mHasSurface=true\n  isOnScreen=true\n  isVisible=true\n"
        "  mTopFocusedDisplayId=0\n")
    BEFORE_LOG = ""
    AFTER_LOG = ("1760212800.100  1425  1425 D TISBinder: onOverviewToggle dispatched\n"
                 "1760212800.101  1425  1425 D OverviewCommandHelper: command queued\n")

    @classmethod
    def tis(cls, focus=0, pending=0, component=None):
        pending_type = "      pendingCommandType=TOGGLE\n" if pending else ""
        return ("SERVICE " + (component or audit.PHONE_TIS_COMPONENT) +
            " 12abc pid=1425 user=0\n"
            "  Client:\n"
            "    OverviewCommandHelper:\n"
            "      pendingCommands=" + str(pending) + "\n" + pending_type +
            "      keyboardFocusTask=Unfocused\n"
            "    Input state:\n"
            "      displays=[0, 2, 3]\n"
            "    TouchState (displayId 0):\n"
            "      mIsUserUnlocked=true\n"
            "    TouchState (displayId 2):\n"
            "      mIsUserUnlocked=true\n"
            "    SystemUiProxy:\n"
            "      mSystemUiProxy=android.os.BinderProxy@abc\n"
            "      mFocusState={FocusState focusedDisplayId=" + str(focus) + "}\n")

    @classmethod
    def overview_xml(cls, label=None):
        raw = card(label or audit.LABELS[audit.COMPONENTS["cancel"]])
        return ('<hierarchy rotation="0"><node package="com.android.launcher3" '
                'resource-id="com.android.launcher3:id/overview_panel" enabled="true" '
                'bounds="[0,0][1080,2400]">' + raw[len("<hierarchy>"):-len("</hierarchy>")] +
                '</node></hierarchy>')

    def real_trace(self, directory, *, activities=None, displays=None, windows=None,
                   overview=None, before_tis=None, after_tis=None,
                   before_log=None, after_log=None, clock=None, cost=None):
        value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
            "11111111-2222-3333-4444-555555555555", "fingerprint", directory, 30)
        switched = False
        self.last_commands = []
        self.last_timeouts = []
        def run(argv, **kwargs):
            nonlocal switched
            self.last_commands.append(list(argv))
            self.last_timeouts.append(kwargs['timeout'])
            tail = argv[6:]
            if clock is not None:
                elapsed = cost(tail) if cost is not None else 1
                limit = kwargs['timeout']
                clock.ns += int(min(elapsed, limit) * 1_000_000_000)
                if elapsed > limit:
                    raise subprocess.TimeoutExpired(argv, limit)
            output = ""
            if tail == ["shell", *audit.PHONE_HOME_RESOLVE]:
                output = audit.PHONE_HOME_COMPONENT + "\n"
            elif tail[:3] == ["exec-out", "cat", tail[-1]]:
                output = (self.overview_xml() if overview is None else overview) if switched else self.HOME_XML
            elif tail == ["shell", *audit.PHONE_TIS_DUMP]:
                output = ((self.tis(focus=2, pending=1) if after_tis is None else after_tis)
                          if switched else
                          (self.tis() if before_tis is None else before_tis))
            elif tail == ["shell", *audit.PHONE_OVERVIEW_LOG]:
                output = ((self.AFTER_LOG if after_log is None else after_log)
                          if switched else
                          (self.BEFORE_LOG if before_log is None else before_log))
            elif tail[:3] == ["shell", "dumpsys", "activity"]:
                output = self.ACTIVITIES if activities is None else activities
            elif tail == ["shell", "dumpsys", "window", "displays"]:
                output = self.DISPLAYS if displays is None else displays
            elif tail == ["shell", "dumpsys", "window", "windows"]:
                output = self.WINDOWS if windows is None else windows
            elif tail == ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_APP_SWITCH"]:
                switched = True
            return subprocess.CompletedProcess(argv, 0, stdout=output)
        with mock.patch.object(producer.subprocess, "run", side_effect=run), \
                mock.patch.object(producer.time, "sleep", side_effect=None if clock is None else clock.sleep), \
                mock.patch.object(producer.time, "monotonic_ns", wraps=producer.time.monotonic_ns) as now:
            if clock is not None:
                now.side_effect = lambda: clock.ns
            value.enter_phone_overview("cancel_menu")
        return value

    def audit_trace(self, directory, value):
        return audit.validate_phone_overview_trace(value.trace, value.container,
            directory, "cancel_menu", 0, len(value.trace))

    def test_real_producer_trace_has_safe_phone_tap_native_focus_and_one_overview_toggle(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.real_trace(directory)
            parsed = self.audit_trace(directory, value)
            self.assertLess(parsed["home"], parsed["tap"])
            self.assertLess(parsed["tap"], parsed["switch"])
            self.assertLess(parsed["switch"], parsed["overview"])
            self.assertEqual(0, parsed["tis_before"]["focused_display_id"])
            self.assertEqual(2, parsed["tis_after"]["focused_display_id"])
            self.assertEqual("TOGGLE", parsed["tis_after"]["pending_command_type"])
            shell = ["docker", "exec", value.container, "adb", "-s", audit.SERIAL, "shell"]
            self.assertTrue(audit.require_consumed_input_inventory(value.trace, shell,
                {parsed["home"], parsed["tap"], parsed["switch"]}))
            self.assertTrue(all(audit.reviewed_command(row["argv"]) for row in value.trace))

    def test_home_workspace_rejects_malformed_wrong_viewport_drawer_duplicate_or_control(self):
        self.assertEqual([540, 1200], audit.phone_home_workspace(self.HOME_XML))
        cases = ("<hierarchy>", self.HOME_XML.replace('rotation="0"', 'rotation="1"'),
            self.HOME_XML.replace('content-desc="Home"', 'content-desc="Apps"'),
            self.HOME_XML.replace(':id/workspace', ':id/apps_list_view'),
            self.HOME_XML.replace('bounds="[0,0][1080,2400]"', 'bounds="[0,0][1081,2400]"'),
            self.HOME_XML.replace('</node></hierarchy>',
                '<node package="com.android.launcher3" resource-id="com.android.launcher3:id/workspace" '
                'enabled="true" bounds="[0,0][1080,2400]"/></node></hierarchy>'),
            self.HOME_XML.replace('</node></hierarchy>',
                '<node package="ordinary.app" enabled="true" clickable="true" '
                'bounds="[500,1100][600,1300]"/></node></hierarchy>'))
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.phone_home_workspace(raw)

    def test_bounded_phone_overview_inventory_accepts_only_exact_owned_raw_paths(self):
        evidence = {}
        for stage in (*audit.SELECTION_STAGES, 'task_remove_card'):
            prefix = 'phone-overview/' + stage + '/'
            names = ['resolve.txt', 'home-00.xml', 'overview-00.xml']
            names += [moment + '-' + kind + '.txt' for moment in ('before', 'after-switch')
                      for kind in ('activities', 'displays', 'windows')]
            names += ['before-tis.txt', 'after-switch-tis.txt']
            names += ['focus-00-' + kind + '.txt' for kind in ('activities', 'displays', 'windows')]
            evidence.update({prefix + name: {} for name in names})
        self.assertEqual(set(evidence), audit.phone_overview_evidence_paths(evidence))
        prefix = 'phone-overview/cancel_menu/'
        for mutation in ('missing', 'gap', 'unbounded', 'foreign', 'alias'):
            changed = copy.deepcopy(evidence)
            if mutation == 'missing': del changed[prefix + 'before-displays.txt']
            elif mutation == 'gap': changed[prefix + 'home-02.xml'] = {}
            elif mutation == 'unbounded':
                changed.update({prefix + 'home-%02d.xml' % index: {} for index in range(9)})
            elif mutation == 'foreign': changed['phone-overview/foreign/home-00.xml'] = {}
            else: changed[prefix + 'focus-00-foreign.txt'] = {}
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.phone_overview_evidence_paths(changed)

    def test_tis_dump_parser_retains_foreign_focus_and_source_defined_queue_state(self):
        before = audit.phone_tis_state(self.tis())
        after = audit.phone_tis_state(self.tis(focus=3, pending=1))
        self.assertEqual({0, 2}, set(before['touch_display_ids']))
        self.assertEqual(0, before['pending_commands'])
        self.assertIsNone(before['pending_command_type'])
        self.assertEqual(3, after['focused_display_id'])
        self.assertEqual('TOGGLE', after['pending_command_type'])

    def test_tis_dump_parser_rejects_alias_missing_duplicate_malformed_and_reserved_state(self):
        valid = self.tis()
        for mutation, raw in (
            ('component_alias', self.tis(component=audit.LAUNCHER + '/.TouchInteractionService')),
            ('system_user', valid.replace(' user=0', ' user=10')),
            ('not_running', valid.replace('pid=1425 user=0', 'pid=(not running)')),
            ('missing_phone', valid.replace('    TouchState (displayId 0):\n'
                                            '      mIsUserUnlocked=true\n', '')),
            ('duplicate_focus', valid + '      mFocusState={FocusState focusedDisplayId=0}\n'),
            ('negative_focus', valid.replace('focusedDisplayId=0', 'focusedDisplayId=-1')),
            ('pending_without_type', valid.replace('pendingCommands=0', 'pendingCommands=1')),
            ('type_without_pending', valid.replace('      keyboardFocusTask=',
                                                    '      pendingCommandType=TOGGLE\n'
                                                    '      keyboardFocusTask=')),
            ('queue_overflow', valid.replace('pendingCommands=0', 'pendingCommands=4')),
            ('duplicate_touch', valid + '    TouchState (displayId 0):\n')):
            with self.subTest(mutation=mutation), self.assertRaises(audit.EvidenceError):
                audit.phone_tis_state(raw)

    def test_remaining_budget_stops_before_mouse_or_toggle_and_bounds_total_runtime(self):
        class Clock:
            def __init__(self): self.ns = 1_000_000_000
            def sleep(self, seconds): self.ns += int(seconds * 1_000_000_000)
        for before in ('mouse', 'toggle'):
            clock = Clock(); start = clock.ns; counts = {}
            def cost(tail):
                key = tuple(tail[:4]); counts[key] = counts.get(key, 0) + 1
                if before == 'mouse':
                    return 20 if tail == ['shell', 'dumpsys', 'window', 'windows'] else 10
                if tail == ['shell', 'dumpsys', 'window', 'windows'] and counts[key] == 2:
                    return 24
                return 6
            with self.subTest(before=before), tempfile.TemporaryDirectory() as temporary, \
                    self.assertRaises(TimeoutError):
                self.real_trace(Path(temporary), clock=clock, cost=cost)
            self.assertLessEqual(clock.ns - start, audit.PHONE_OVERVIEW_TIMEOUT_NS)
            self.assertFalse(any('KEYCODE_APP_SWITCH' in argv for argv in self.last_commands))
            if before == 'mouse': self.assertFalse(any('mouse' in argv for argv in self.last_commands))
            else: self.assertTrue(any('mouse' in argv for argv in self.last_commands))
            self.assertTrue(all(0 < value <= 30 for value in self.last_timeouts))
        clock = Clock(); start = clock.ns
        with tempfile.TemporaryDirectory() as temporary:
            value = self.real_trace(Path(temporary), clock=clock)
            self.audit_trace(Path(temporary), value)
        self.assertLess(clock.ns - start, audit.PHONE_OVERVIEW_TIMEOUT_NS)

    def test_hierarchy_budget_is_rechecked_before_dump_cat_and_cleanup(self):
        clock = mock.Mock(); clock.ns = 1_000_000_000
        with tempfile.TemporaryDirectory() as temporary:
            value = producer.Producer('a' * 64, 'sha256:' + 'b' * 64,
                '11111111-2222-3333-4444-555555555555', 'fingerprint', Path(temporary), 30)
            calls = []
            def run(argv, **kwargs):
                calls.append((argv, kwargs['timeout']))
                clock.ns += 5_000_000_000
                return subprocess.CompletedProcess(argv, 0, stdout='raw\n')
            with mock.patch.object(producer.time, 'monotonic_ns', side_effect=lambda: clock.ns), \
                    mock.patch.object(producer.subprocess, 'run', side_effect=run), \
                    self.assertRaises(TimeoutError):
                value.hierarchy(deadline_ns=clock.ns + 5_000_000_000)
            self.assertEqual(1, len(calls))
            self.assertIn('dump', calls[0][0]); self.assertEqual(5, calls[0][1])

    def test_native_home_focus_rejects_wrong_display_window_task_and_ambiguity(self):
        audit.phone_home_focus(self.ACTIVITIES, self.DISPLAYS, self.WINDOWS)
        cases = ((self.ACTIVITIES.replace('state=RESUMED', 'state=PAUSED'), self.DISPLAYS, self.WINDOWS),
            (self.ACTIVITIES.replace(' t9}', ' t10}', 1), self.DISPLAYS, self.WINDOWS),
            (self.ACTIVITIES + self.ACTIVITIES, self.DISPLAYS, self.WINDOWS),
            (self.ACTIVITIES, self.DISPLAYS.replace('mDisplayId=0', 'mDisplayId=2'), self.WINDOWS),
            (self.ACTIVITIES, self.DISPLAYS.replace('Window{def', 'Window{aaa'), self.WINDOWS),
            (self.ACTIVITIES, self.DISPLAYS.replace(' t9}', ' t10}'), self.WINDOWS),
            (self.ACTIVITIES, self.DISPLAYS + self.DISPLAYS, self.WINDOWS),
            (self.ACTIVITIES, self.DISPLAYS, self.WINDOWS.replace('mTopFocusedDisplayId=0', 'mTopFocusedDisplayId=2')),
            (self.ACTIVITIES, self.DISPLAYS, self.WINDOWS.replace('isVisible=true', 'isVisible=false')),
            (self.ACTIVITIES, self.DISPLAYS, self.WINDOWS + '  mTopFocusedDisplayId=0\n'))
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.phone_home_focus(*raw)

    def test_all_native_singleton_rows_reject_mixed_foreign_home_null_or_malformed_fields(self):
        originals = (self.ACTIVITIES, self.DISPLAYS, self.WINDOWS)
        for raw_index, field, home, foreign in (
            (0, 'topResumedActivity=', 'ActivityRecord{abc u0 ' + audit.PHONE_HOME_COMPONENT + ' t9}',
                'ActivityRecord{bad u0 ordinary.app/.Activity t10}'),
            (0, 'ResumedActivity: ', 'ActivityRecord{abc u0 ' + audit.PHONE_HOME_COMPONENT + ' t9}',
                'ActivityRecord{bad u0 ordinary.app/.Activity t10}'),
            (1, 'mCurrentFocus=', 'Window{def u0 ' + audit.PHONE_HOME_WINDOW + '}',
                'Window{bad u0 ordinary.app/.Activity}'),
            (1, 'mFocusedApp=', 'ActivityRecord{abc u0 ' + audit.PHONE_HOME_COMPONENT + ' t9}',
                'ActivityRecord{bad u0 ordinary.app/.Activity t10}')):
            for mode in ('foreign_before', 'foreign_after', 'null_singleton', 'malformed_singleton', 'foreign_singleton'):
                raw = list(originals)
                original = field + home
                if mode == 'foreign_before': replacement = field + foreign + '\n  ' + original
                elif mode == 'foreign_after': replacement = original + '\n  ' + field + foreign
                elif mode == 'null_singleton': replacement = field + 'null'
                elif mode == 'malformed_singleton': replacement = field + 'unparseable'
                else: replacement = field + foreign
                self.assertIn(original, raw[raw_index])
                raw[raw_index] = raw[raw_index].replace(original, replacement)
                with self.subTest(field=field, mode=mode), self.assertRaises(audit.EvidenceError):
                    audit.phone_home_focus(*raw)

    def test_overview_requires_taskview_snapshot_not_home_actions_drawer_or_foreign_label(self):
        overview = self.overview_xml()
        self.assertTrue(audit.phone_overview(overview))
        for raw in (self.HOME_XML, '<hierarchy rotation="0"/>', overview.replace(':id/task_view_single', ':id/icon'),
                    overview.replace(':id/snapshot', ':id/text'), overview.replace('com.android.launcher3', 'ordinary.app'),
                    overview.replace('rotation="0"', 'rotation="1"'),
                    overview.replace('</node></hierarchy>', '<node package="com.android.launcher3" '
                        'resource-id="com.android.launcher3:id/apps_view" enabled="true"/></node></hierarchy>')):
            with self.subTest(raw=raw), self.assertRaises(audit.EvidenceError):
                audit.phone_overview(raw)
        with self.assertRaises(audit.EvidenceError):
            audit.recents_card(self.overview_xml('ordinary app label'), audit.LABELS[audit.COMPONENTS["cancel"]])

    def test_producer_never_toggles_before_real_phone_focus_and_never_repeats_toggle(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(audit.EvidenceError):
            self.real_trace(Path(temporary), windows=self.WINDOWS.replace('mTopFocusedDisplayId=0', 'mTopFocusedDisplayId=2'))
        self.assertFalse(any('KEYCODE_APP_SWITCH' in argv for argv in self.last_commands))
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(audit.EvidenceError):
            self.real_trace(Path(temporary), overview=self.HOME_XML)
        self.assertEqual(1, sum('KEYCODE_APP_SWITCH' in argv for argv in self.last_commands))
        self.assertFalse(any('swipe' in argv for argv in self.last_commands))

    def test_independent_auditor_rejects_changed_source_order_input_timeout_and_duplicates(self):
        for mutation in ('source', 'order', 'mouse_display', 'toggle_duplicate', 'timeout',
                         'hierarchy_duplicate', 'raw_changed', 'overview_home', 'focus_display',
                         'after_switch_display', 'tis_source', 'tis_component', 'tis_raw_changed',
                         'tis_order', 'tis_timeout', 'tis_alias', 'log_source'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary); value = self.real_trace(directory)
                def row(suffix):
                    return next(item for item in value.trace if item.get('evidence', '').endswith(suffix))
                if mutation == 'source': row('focus-00-displays.txt')['argv'][-1] = 'windows'
                elif mutation == 'order':
                    left = value.trace.index(row('focus-00-displays.txt')); right = value.trace.index(row('focus-00-windows.txt'))
                    value.trace[left], value.trace[right] = value.trace[right], value.trace[left]
                elif mutation == 'mouse_display':
                    next(item for item in value.trace if 'mouse' in item['argv'])['argv'][-4] = '2'
                elif mutation == 'toggle_duplicate':
                    value.trace.append(copy.deepcopy(next(item for item in value.trace if 'KEYCODE_APP_SWITCH' in item['argv'])))
                elif mutation == 'timeout': row('overview-00.xml')['ended_monotonic_ns'] += audit.PHONE_OVERVIEW_TIMEOUT_NS
                elif mutation == 'hierarchy_duplicate': value.trace.append(copy.deepcopy(row('home-00.xml')))
                elif mutation == 'tis_source': row('before-tis.txt')['argv'][-1] = audit.LAUNCHER + '/.TouchInteractionService'
                elif mutation == 'tis_order':
                    left = value.trace.index(row('before-tis.txt'))
                    right = next(index for index, item in enumerate(value.trace)
                                 if item.get('argv', [])[-len(audit.PHONE_OVERVIEW_LOG):] ==
                                 list(audit.PHONE_OVERVIEW_LOG))
                    value.trace[left], value.trace[right] = value.trace[right], value.trace[left]
                elif mutation == 'tis_timeout':
                    row('after-switch-tis.txt')['ended_monotonic_ns'] += audit.PHONE_OVERVIEW_TIMEOUT_NS
                elif mutation == 'tis_alias':
                    row('before-tis.txt')['evidence'] = 'phone-overview/cancel_menu/tis-before.txt'
                elif mutation == 'log_source':
                    logs = [item for item in value.trace if item.get('argv', [])[-len(audit.PHONE_OVERVIEW_LOG):] ==
                            list(audit.PHONE_OVERVIEW_LOG)]
                    logs[0]['argv'][-2] = 'ActivityTaskManager:D'
                else:
                    suffix = {'raw_changed': 'home-00.xml', 'overview_home': 'overview-00.xml',
                              'focus_display': 'focus-00-windows.txt',
                              'after_switch_display': 'after-switch-windows.txt',
                              'tis_component': 'before-tis.txt',
                              'tis_raw_changed': 'after-switch-tis.txt'}[mutation]
                    target = row(suffix); path = directory / target['evidence']
                    raw = (self.tis(component=audit.LAUNCHER + '/.TouchInteractionService')
                           if mutation == 'tis_component' else
                           self.tis(focus=2, pending=1) + ' '
                           if mutation == 'tis_raw_changed' else
                           self.HOME_XML if mutation == 'overview_home' else
                           self.WINDOWS.replace('mTopFocusedDisplayId=0', 'mTopFocusedDisplayId=2')
                           if mutation in ('focus_display', 'after_switch_display') else self.HOME_XML + ' ')
                    path.write_text(raw)
                    if mutation not in ('raw_changed', 'tis_raw_changed'):
                        target['output_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
                with self.assertRaises(audit.EvidenceError): self.audit_trace(directory, value)

    def test_independent_auditor_retains_stale_or_foreign_quickstep_focus_as_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            value = self.real_trace(directory, after_tis=self.tis(focus=99, pending=1))
            parsed = self.audit_trace(directory, value)
            self.assertEqual(99, parsed['tis_after']['focused_display_id'])

    def test_failed_home_hierarchy_never_triggers_blind_card_search_swipes(self):
        with tempfile.TemporaryDirectory() as temporary:
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint",
                Path(temporary), 30)
            calls = []
            value.runtime_command = lambda phase: None
            value.home = lambda: None
            value.shell = lambda *argv, **kwargs: calls.append(argv) or ""
            value.hierarchy = lambda **kwargs: self.HOME_XML
            with mock.patch.object(producer.time, "sleep"), self.assertRaises(
                    (ValueError, audit.EvidenceError, TimeoutError)):
                value.open_menu(audit.COMPONENTS["cancel"], "cancel_menu")
            self.assertFalse(any("swipe" in argv for argv in calls),
                             "Home was treated as a horizontally searchable Recents card list")


class FailedPartialInstrumentationTests(unittest.TestCase):
    def test_failed_empty_running_stream_is_sealed_without_terminal_success_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            value.instrument_path.parent.mkdir()
            value.instrument_file = value.instrument_path.open("xb")
            process = mock.Mock()
            process.poll.side_effect = [None, -15]
            process.wait.return_value = -15
            value.instrument = process
            value._record({"kind": "background_start", "id": "instrumentation-" + value.conformance_run,
                           "argv": ["synthetic-no-execution"], "started_monotonic_ns": 1})
            value.stop_background()
            receipt = value.seal_failure(ValueError("primary missing-card failure"))
            failed = json.loads((output / "failure.json").read_bytes())
            self.assertEqual("primary missing-card failure", failed["error"])
            self.assertEqual("failed_not_qualified", failed["status"])
            self.assertEqual({"path": "identity/instrumentation.txt",
                              "bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()},
                             failed["instrumentation"])
            status = failed["instrumentation_status"]
            self.assertEqual("partial_no_terminal_finish", status["completeness"])
            self.assertFalse(status["terminal_finish_recorded"])
            self.assertFalse(status["terminal_success_qualified"])
            self.assertEqual(-15, status["background_cleanup"]["returncode"])
            self.assertTrue(status["background_cleanup"]["terminate_sent"])
            self.assertTrue(status["background_cleanup"]["output_closed"])
            self.assertFalse(status["background_cleanup"]["kill_sent"])
            self.assertEqual(value.trace, json.loads((output / "commands.json").read_bytes()))
            self.assertEqual(audit.file_ref(output / "failure.json"),
                             {key: receipt[key] for key in ("sha256", "bytes")})
            self.assertEqual(b"", value.instrument_path.read_bytes())
            self.assertFalse((output / "report.json").exists())
            with self.assertRaises(audit.EvidenceError):
                audit.file_ref(value.instrument_path)

    def test_failed_ref_binds_empty_and_nonempty_partial_bytes_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "partial.txt"
            for payload in (b"", b"INSTRUMENTATION_RESULT: sta", b"arbitrary rejected output\n"):
                path.write_bytes(payload)
                self.assertEqual({"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()},
                                 producer.failed_file_ref(path))

    def test_failed_ref_rejects_alias_special_overlimit_and_invalid_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ordinary = root / "ordinary"; ordinary.write_bytes(b"abcd")
            linked = root / "linked"; linked.symlink_to(ordinary)
            dangling = root / "dangling"; dangling.symlink_to(root / "missing")
            directory = root / "directory"; directory.mkdir()
            fifo = root / "fifo"; __import__("os").mkfifo(fifo)
            parent_link = root / "parent-link"; parent_link.symlink_to(root, target_is_directory=True)
            for path in (linked, dangling, directory, fifo, parent_link / "ordinary"):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    producer.failed_file_ref(path)
            with self.assertRaisesRegex(ValueError, "Invalid failed-only evidence file"):
                producer.failed_file_ref(ordinary, maximum=3)
            for bound in (True, 0, -1, 1.5):
                with self.subTest(bound=bound), self.assertRaises(ValueError):
                    producer.failed_file_ref(ordinary, maximum=bound)

    def test_failed_ref_detects_fd_substitution_and_midread_stat_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "original"; path.write_bytes(b"same")
            other = root / "other"; other.write_bytes(b"same")
            actual_open = producer.os.open
            with mock.patch.object(producer.os, "open", side_effect=lambda _path, flags:
                    actual_open(other, flags)), self.assertRaisesRegex(ValueError, "changed before read"):
                producer.failed_file_ref(path)
            actual_fstat = producer.os.fstat
            count = 0
            def observation(descriptor):
                nonlocal count
                count += 1
                result = actual_fstat(descriptor)
                if count == 3:
                    values = {key: getattr(result, key) for key in
                              ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")}
                    values["st_size"] += 1
                    return __import__("types").SimpleNamespace(**values)
                return result
            with mock.patch.object(producer.os, "fstat", side_effect=observation), \
                 self.assertRaisesRegex(ValueError, "changed while being read"):
                producer.failed_file_ref(path)

    def test_failed_ref_nonblocking_fd_rejects_fifo_swap_without_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "original"; path.write_bytes(b"")
            actual_open = producer.os.open
            def swap(_path, flags):
                self.assertTrue(flags & producer.os.O_NONBLOCK)
                self.assertTrue(flags & producer.os.O_NOFOLLOW)
                path.unlink(); producer.os.mkfifo(path)
                return actual_open(path, flags)
            with mock.patch.object(producer.os, "open", side_effect=swap), \
                 self.assertRaisesRegex(ValueError, "changed before read"):
                producer.failed_file_ref(path)

    def test_failure_seal_refuses_open_writer_and_dangling_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            value.instrument_path.parent.mkdir()
            value.instrument_file = value.instrument_path.open("xb")
            try:
                with self.assertRaisesRegex(ValueError, "Stop background instrumentation"):
                    value.seal_failure(ValueError("primary failure"))
            finally:
                value.stop_background()
            value.instrument_path.unlink(); value.instrument_path.symlink_to(output / "missing")
            with self.assertRaisesRegex(ValueError, "Aliased failed instrumentation evidence"):
                value.seal_failure(ValueError("primary failure"))
            self.assertFalse((output / "failure.json").exists())

    def test_forced_kill_cleanup_disposition_is_retained_without_pass_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            value.instrument_path.parent.mkdir()
            value.instrument_file = value.instrument_path.open("xb")
            process = mock.Mock(); process.poll.side_effect = [None, -9]
            process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 10), -9]
            value.instrument = process
            value.stop_background(); value.seal_failure(ValueError("primary failure"))
            failed = json.loads((output / "failure.json").read_bytes())
            status = failed["instrumentation_status"]
            self.assertTrue(status["background_cleanup"]["terminate_sent"])
            self.assertTrue(status["background_cleanup"]["kill_sent"])
            self.assertEqual(-9, status["background_cleanup"]["returncode"])
            self.assertTrue(status["background_cleanup"]["output_closed"])
            self.assertIsNone(status["background_cleanup"]["error"])
            self.assertFalse(status["terminal_success_qualified"])
            self.assertFalse((output / "report.json").exists())

    def test_cleanup_error_is_not_swallowed_or_labeled_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            value = producer.Producer("a" * 64, "sha256:" + "b" * 64,
                "11111111-2222-3333-4444-555555555555", "fingerprint", output, 30)
            value.instrument_path.parent.mkdir()
            value.instrument_file = value.instrument_path.open("xb")
            process = mock.Mock(); process.poll.return_value = None
            process.wait.side_effect = RuntimeError("wait failure")
            value.instrument = process
            try:
                with self.assertRaisesRegex(RuntimeError, "wait failure"):
                    value.stop_background()
                self.assertEqual("wait failure", value.background_cleanup["error"])
                self.assertFalse(value.background_cleanup["output_closed"])
                self.assertIsNone(value.background_cleanup["returncode"])
            finally:
                value.instrument_file.close(); value.instrument_file = None


class RecentsParserTests(unittest.TestCase):
    def test_candidate_manifest_binds_the_exact_system_image_set(self):
        def apk(package, digest, targets, debuggable, certificate="e" * 64):
            return {"sha256": digest, "bytes": 1, "package": package,
                "version_code": 1, "version_name": "1",
                "certificate_der_sha256": certificate, "signers": 1,
                "schemes": {"3": True}, "debuggable": debuggable,
                "test_only": False, "instrumentation_targets": targets,
                "shared_uid": False, "privileged_manifest": False}
        conformance, fixture = "a" * 64, "b" * 64
        fingerprint = "Android/sdk_phone64_x86_64/emu64x:test"
        value = {"schema": 1, "kind": "phase1_fresh_guest_conformance_candidate_v1",
            "scope": "unqualified_phase1_fresh_guest_os_contract_conformance_candidate",
            "architecture": "amd64", "api": 3, "fingerprint": fingerprint,
            "files": {audit.BUNDLED_APKS[audit.APP]: conformance,
                      audit.BUNDLED_APKS[audit.FIXTURE]: fixture},
            "product_images": {name: "c" * 64 for name in audit.PRODUCT_IMAGES},
            "os_artifacts": {name: "d" * 64 for name in audit.OS_GUEST_PATHS},
            "base_product_candidate": {}, "packet": {},
            "artifacts": {"wonad": apk(audit.APP, "f" * 64, [], False),
                "conformance": apk(audit.APP, conformance, [audit.APP], False),
                "fixture": apk(audit.FIXTURE, fixture, [], True, "1" * 64), "fault": {}},
            "conformance_version_update": {}, "update_data_canary": {},
            "systemui_fault_identity": {}, "planned_runtime_gates": {},
            "runtime_qualified": False, "guests_started": False,
            "hardware": "emulator_only", "unofficial": True,
            "production_identity": False, "product_apk_present": False}
        raw = json.dumps(value)
        self.assertEqual(fingerprint, audit.candidate_manifest(raw, fingerprint)["fingerprint"])
        for mutation in ("missing", "malformed"):
            changed = copy.deepcopy(value)
            if mutation == "missing":
                changed["product_images"].pop(audit.SYSTEM_IMAGE)
            else:
                changed["product_images"][audit.SYSTEM_IMAGE] = "not-a-digest"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    audit.EvidenceError, "exact unqualified conformance candidate"):
                audit.candidate_manifest(json.dumps(changed), fingerprint)
        changed = copy.deepcopy(value)
        changed["artifacts"]["conformance"]["certificate_der_sha256"] = "2" * 64
        with self.assertRaisesRegex(audit.EvidenceError, "signer relationship"):
            audit.candidate_manifest(json.dumps(changed), fingerprint)

    def test_active_privileged_package_rejects_data_update_or_alias(self):
        path = audit.PRIVILEGED_SYSTEM_PACKAGES[audit.LAUNCHER]
        self.assertEqual(path, audit.active_system_package_path(
            "package:" + path, audit.LAUNCHER))
        for raw in ("package:/data/app/launcher/base.apk",
                    "package:" + path + "\npackage:/data/app/launcher/base.apk"):
            with self.subTest(raw=raw), self.assertRaisesRegex(
                    audit.EvidenceError, "immutable candidate system package"):
                audit.active_system_package_path(raw, audit.LAUNCHER)

    def test_every_fixture_observation_family_is_parsed_and_marker_bound(self):
        cases = (
            ("WONAD_OBSERVATION ", audit.FIXTURE + "/.LaunchActivity"),
            ("WONAD_PERMISSION ", audit.FIXTURE + "/.PermissionActivity"),
            ("WONAD_PALETTE ", audit.FIXTURE + "/.PaletteOneActivity"),
            ("WONAD_BANDED_PALETTE ", audit.FIXTURE + "/.BandedOneActivity"),
        )
        for index, (marker, component) in enumerate(cases, start=40):
            observation = record(component, index)
            if marker == "WONAD_PERMISSION ":
                observation = {key: value for key, value in observation.items()
                               if key not in {"left", "top", "right", "bottom",
                                              "key_downs", "pointer_downs", "mouse_downs"}}
                observation.update(schema=1, uid=UIDS[audit.FIXTURE],
                    bounds=[0, 0, 900, 1000], key_requests=0, button_requests=0)
            raw = ("TASK 10181:x id=%d userId=0 displayId=0(type=INTERNAL)\n    %s%s\n" %
                   (index, marker, json.dumps(observation)))
            with self.subTest(marker=marker):
                parsed, membership = audit.fixture_records(raw)
                self.assertEqual(index, parsed[component]["task"])
                self.assertEqual(0, membership[index])
                self.assertEqual((0, 0, 900, 1000), tuple(parsed[component][key]
                    for key in ("left", "top", "right", "bottom")))
        wrong = record(audit.FIXTURE + "/.BandedOneActivity", 99)
        raw = ("TASK 10181:x id=99 userId=0 displayId=0(type=INTERNAL)\n"
               "    WONAD_OBSERVATION " + json.dumps(wrong) + "\n")
        with self.assertRaises(audit.EvidenceError):
            audit.fixture_records(raw)

    def test_home_parser_binds_leaf_task_not_root_home_task(self):
        raw = ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
               "Display #2 (activities from top to bottom):\n"
               "  * Task{aaaaaaa #30 type=home U=0 visible=true}\n"
               "    * Task{bbbbbbb #31 type=home A=10180:org.wonad.desktop U=0 rootTaskId=30}\n"
               "      * Hist #0: ActivityRecord{ccccccc u0 org.wonad.desktop/.ExternalHomeActivity t31}\n"
               "ActivityTaskSupervisor state:\n  synthetic supervisor summary\n")
        windows = ("  Window #0 Window{ddddddd u0 org.wonad.desktop/org.wonad.desktop.ExternalHomeActivity}:\n"
                   "    mDisplayId=2 taskId=31 mOwnerUid=10180 mHasSurface=true SECURE\n"
                   "    mActivityRecord=ActivityRecord{ccccccc u0 org.wonad.desktop/.ExternalHomeActivity t31}\n"
                   "    mDrawState=HAS_DRAWN\n")
        inputs = ("0: name=ddddddd org.wonad.desktop/org.wonad.desktop.ExternalHomeActivity, "
                  "displayId=2, ownerUid=10180, inputConfig=NOT_FOCUSABLE,\n")
        parsed = audit.home_incarnations(raw, windows, inputs, UIDS[audit.APP], {2: display(2, 1)})
        self.assertEqual({"task": 31, "task_object": "bbbbbbb", "activity_record": "ccccccc"},
                         {key: parsed[2][key] for key in ("task", "task_object", "activity_record")})
        with self.assertRaises(audit.EvidenceError):
            audit.home_incarnations(raw.replace("#31 type=home", "#32 type=home"),
                                    windows, inputs, UIDS[audit.APP], {2: display(2, 1)})
        with self.assertRaisesRegex(audit.EvidenceError, "window/input"):
            audit.home_incarnations(raw, windows, inputs.replace("name=ddddddd", "name=eeeeeee"),
                                    UIDS[audit.APP], {2: display(2, 1)})

    def test_shell_parser_joins_window_and_input_token_and_owner_uid(self):
        raw = ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
               "Display #2 (activities from top to bottom):\n"
               "  * Task{aaaaaaa #31 U=0}\n"
               "    * Hist #0: ActivityRecord{bbbbbbb u0 org.wonad.desktop/.ExternalShellActivity t31}\n"
               "      dat=wonad-shell://77/1002\n"
               "ActivityTaskSupervisor state:\n  synthetic supervisor summary\n")
        component = "org.wonad.desktop/org.wonad.desktop.ExternalShellActivity"
        windows = ("  Window #0 Window{ccccccc u0 %s}:\n"
                   "    mDisplayId=2 mOwnerUid=%d mHasSurface=true SECURE\n"
                   "    mActivityRecord=ActivityRecord{bbbbbbb u0 org.wonad.desktop/.ExternalShellActivity t31}\n"
                   "    mDrawState=HAS_DRAWN\n"
                   "    isOnScreen=true isVisible=true\n" % (component, UIDS[audit.APP]))
        inputs = ("0: name=ccccccc %s, displayId=2, ownerUid=%d, "
                  "inputConfig=NOT_FOCUSABLE,\n" % (component, UIDS[audit.APP]))
        parsed = audit.shell_incarnations(raw, windows, inputs, 77, UIDS[audit.APP],
                                          {2: display(2, 1)})
        self.assertEqual(1002, parsed[2]["token"])
        for changed_windows, changed_inputs in (
                (windows, inputs.replace("name=ccccccc", "name=ddddddd")),
                (windows.replace("mOwnerUid=%d" % UIDS[audit.APP], "mOwnerUid=999"), inputs),
                (windows.replace("isVisible=true", "isVisible=false"), inputs),
                (windows, inputs.replace("NOT_FOCUSABLE", "NOT_FOCUSABLE|NOT_VISIBLE")),
                (windows, inputs.replace("NOT_FOCUSABLE", "NOT_FOCUSABLE|DROP_INPUT"))):
            with self.assertRaisesRegex(audit.EvidenceError, "window/input"):
                audit.shell_incarnations(raw, changed_windows, changed_inputs, 77,
                                         UIDS[audit.APP], {2: display(2, 1)})

    def test_launcher_controls_require_trusted_package_id_state_and_geometry(self):
        xml = menu()
        self.assertEqual([300, 485], audit.launcher_control(xml, "Send to Wonad"))
        for changed in (xml.replace("com.android.launcher3", audit.APP),
                        xml.replace(":id/text", ":id/forged"),
                        xml.replace('enabled="true"', 'enabled="false"'),
                        xml.replace('clickable="true" enabled="true" bounds="[80,420]',
                                    'clickable="false" enabled="true" bounds="[80,420]'),
                        xml.replace("[100,440][500,530]", "[100,440][1500,530]"),
                        xml + xml):
            with self.subTest(xml=changed[:80]), self.assertRaises((audit.EvidenceError, audit.ET.ParseError)):
                audit.launcher_control(changed, "Send to Wonad")

    def test_stage_manifest_rejects_aliases_reordering_and_fake_selection(self):
        rows = []
        for ordinal, name in enumerate(audit.STAGES):
            prefix = "stages/%02d-%s/" % (ordinal, name)
            rows.append({"name": name, "ordinal": ordinal,
                "trace_start": 10 + ordinal * 10, "trace_end": 19 + ordinal * 10,
                "files": {kind: prefix + kind + (".xml" if kind == "hierarchy" else ".txt")
                          for kind in audit.CAPTURE_KINDS},
                "frames": {"0": prefix + "frame-0.png"},
                "selection": ("selections/%02d-%s.xml" % (ordinal, name)
                              if name in audit.SELECTION_STAGES else None)})
        expected = sum(len(row["files"]) + len(row["frames"]) +
                       (row["selection"] is not None) for row in rows)
        self.assertEqual(expected, len(audit.validate_stage_manifest(rows)))
        mutations = []
        overlap = copy.deepcopy(rows); overlap[1]["trace_start"] = overlap[0]["trace_end"] - 1
        mutations.append(overlap)
        alias = copy.deepcopy(rows); alias[2]["files"]["fixture"] = alias[1]["files"]["fixture"]
        mutations.append(alias)
        fake_selection = copy.deepcopy(rows); fake_selection[0]["selection"] = "selections/fake.xml"
        mutations.append(fake_selection)
        missing_selection = copy.deepcopy(rows); missing_selection[1]["selection"] = None
        mutations.append(missing_selection)
        for changed in mutations:
            with self.subTest(stage=changed[1]["name"]), self.assertRaises(audit.EvidenceError):
                audit.validate_stage_manifest(changed)

    def test_command_review_rejects_every_privileged_shortcut(self):
        safe = ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell", "input",
                "touchscreen", "-d", "0", "tap", "1", "2"]
        self.assertTrue(audit.reviewed_command(safe))
        for tail in (("shell", "cmd", "package", "list", "packages", "-U",
                      "--user", "0", audit.APP),
                     ("shell", "cmd", "package", "list", "packages", "-U",
                      "--user", "0", "--uid", "10180")):
            self.assertTrue(audit.reviewed_command(
                ["docker", "exec", "c", "adb", "-s", audit.SERIAL, *tail]))
        for tail in (("shell", "am", "task", "move-to-display"),
                     ("shell", "am", "start-activity", "-n", audit.FIXTURE + "/.LaunchActivity"),
                     ("shell", "cmd", "activity", "start-activity", "-n",
                      audit.FIXTURE + "/.LaunchActivity"),
                     ("shell", "am", "force-stop", audit.FIXTURE),
                     ("shell", "settings", "put", "secure", "x", "1"),
                     ("shell", "pm", "clear", audit.FIXTURE),
                     ("shell", "cmd", "package", "list", "packages", "-U", audit.APP),
                     ("shell", "cmd", "package", "list", "packages", "-U",
                      "--user", "10", audit.APP),
                     ("shell", "wm", "size", "1x1")):
            with self.subTest(tail=tail), self.assertRaises(audit.EvidenceError):
                audit.reviewed_command(["docker", "exec", "c", "adb", *tail])
        for argv in (["docker", "exec", "c", "sh", "-c", "adb shell am start x"],
                     ["docker", "exec", "c", "adb", "-s", audit.SERIAL, "shell",
                      "input", "tap", "1", "2;am start x"]):
            with self.subTest(argv=argv), self.assertRaises(audit.EvidenceError):
                audit.reviewed_command(argv)

    def test_runtime_status_duplicate_or_foreign_state_fails(self):
        displays = {2: display(2, 1)}
        good = "WONAD_CONFORMANCE_STATUS " + json.dumps(session_status(displays)) + "\n"
        self.assertEqual("ready", audit.runtime_status(good)["state"])
        for raw in (good + good, good.replace('"state": "ready"', '"state": "claimed"'),
                    'WONAD_CONFORMANCE_STATUS {"schema":1,"schema":1}\n'):
            with self.assertRaises(audit.EvidenceError): audit.runtime_status(raw)

    def test_png_parser_rejects_label_bytes_and_binds_geometry(self):
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
        pixel = bytes.fromhex("cc4422")
        raw = (b"\x00" + pixel * 3) * 2
        payload = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 3, 2, 8, 2, 0, 0, 0)) +
                   chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
        info = audit.png_info(payload)
        self.assertEqual((3, 2), tuple(info[key] for key in ("width", "height")))
        self.assertEqual(6, info["known_colors"]["cc4422"])
        with self.assertRaises(audit.EvidenceError): audit.png_info(b"Screenshot")
        damaged = bytearray(payload); damaged[-5] ^= 1
        with self.assertRaises(audit.EvidenceError): audit.png_info(bytes(damaged))

    def test_producer_has_every_stage_and_no_direct_private_or_task_move_call(self):
        source = Path(producer.__file__).read_text()
        # capture() itself enforces the complete auditor-owned stage sequence;
        # the three transfer pairs are deliberately emitted by a loop.
        self.assertIn("name == acceptance.STAGES[len(self.stages)]", source)
        self.assertIn("len(self.stages) == len(acceptance.STAGES)", source)
        for name in set(audit.STAGES) - {
                "transfer_1_menu", "transfer_1_done", "transfer_2_menu",
                "transfer_2_done", "transfer_3_menu", "transfer_3_done"}:
            self.assertIn('capture("' + name + '"', source)
        self.assertIn('self.capture(stage_name, selection)', source)
        self.assertIn('capture(f"transfer_{slot}_done"', source)
        self.assertNotIn('"am", "task"', source)
        self.assertNotIn('"settings", "--user", "0", "put"', source)
        self.assertNotIn('NativeDesktopController', source)
        self.assertIn("acceptance.audit_report", source)


if __name__ == "__main__":
    unittest.main()
