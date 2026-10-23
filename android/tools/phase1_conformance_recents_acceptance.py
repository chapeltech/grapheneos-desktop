#!/usr/bin/env python3
"""Independent auditor for the Phase-1 conformance-client Recents lane.

The producer's booleans and UI labels are never acceptance evidence.  This
module reopens the raw Android activity/window/input/display/service/log dumps,
the original Launcher hierarchies, the command journal and real emulator
framebuffers.  It then reconstructs the exact Task, ActivityRecord, display,
session-generation and connector-incarnation relationships for every action.

The lane is intentionally separate from the product-Wonad Recents test.  It is
designed for the policy-free ``org.wonad.desktop`` conformance APK and does not
start an emulator or mutate Android while auditing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import xml.etree.ElementTree as ET
import zlib


SCHEMA = 1
KIND = "wonad-phase1-conformance-recents-run"
SCOPE = "fresh-conformance-apk-three-display-phone-recents"
SERIAL = "emulator-5580"
APP = "org.wonad.desktop"
FIXTURE = "org.wonad.fixture"
LAUNCHER = "com.android.launcher3"
SYSTEMUI = "com.android.systemui"
OS_GUEST_PATHS = {
    "com.android.systemui": "/system_ext/priv-app/SystemUI/SystemUI.apk",
    "os_broker_native": "/system_ext/lib64/libwonad_broker_jni.so",
    "os_input_native": "/system/lib64/libwonad_input_jni.so",
    "os_input_dispatcher": "/system/lib64/libinputflinger.so",
    "os_android_servers": "/system/lib64/libandroid_servers.so",
    "os_services": "/system/framework/services.jar",
    "os_framework": "/system/framework/framework.jar",
}
PRIVILEGED_SYSTEM_PACKAGES = {
    LAUNCHER: "/system_ext/priv-app/Launcher3QuickStep/Launcher3QuickStep.apk",
    SYSTEMUI: OS_GUEST_PATHS[SYSTEMUI],
}
SYSTEM_IMAGE = "system-qemu.img"
PRODUCT_IMAGES = {
    "system-qemu.img", "vendor-qemu.img", "ramdisk-qemu.img", "userdata.img",
    "encryptionkey.img", "kernel-ranchu", "advancedFeatures.ini", "kernel_cmdline.txt",
    "VerifiedBootParams.textproto", "system/build.prop",
    "build_fingerprint-sdk_phone64_x86_64.txt",
}
BUNDLED_APKS = {
    APP: "/opt/wonad/phase1-conformance/conformance.apk",
    FIXTURE: "/opt/wonad/phase1-conformance/fixture.apk",
}
# Main-buffer action markers are isolated without ever erasing ActivityManager's
# cumulative event buffer.  The enclosing fresh-guest audit can therefore read
# every am_anr/am_crash emitted before, during or after this lane.
LOG_CLEAR = ("logcat", "-b", "main", "-c")
SHA256 = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
RUN_ID = re.compile(r"[0-9a-f]{32}")
BOOT_ID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}")
FIRST_APPLICATION_UID = 10000
LAST_APPLICATION_UID = 19999

DISPLAY_SPECS = {
    1: (4000, 2000, 160),
    2: (1920, 1080, 240),
    3: (2560, 1440, 320),
}

FIXTURE_COLORS = {
    FIXTURE + "/.OneActivity": ("90caf9",),
    FIXTURE + "/.TwoActivity": ("ffcc80",),
    FIXTURE + "/.LaunchActivity": ("b9e4c9",),
    FIXTURE + "/.PermissionActivity": ("ead8b7",),
    FIXTURE + "/.PaletteOneActivity": ("cc4422",),
    FIXTURE + "/.PaletteTwoActivity": ("22aa66",),
    FIXTURE + "/.BandedOneActivity": ("cc4422", "ff8844", "ffc488"),
    FIXTURE + "/.BandedTwoActivity": ("22aa66", "66dd88", "aaffcc"),
    FIXTURE + "/.BandedThreeActivity": ("7744bb", "aa77ee", "ddbbff"),
    FIXTURE + "/.BandedFourActivity": ("2266cc", "55aaff", "99ddff"),
    FIXTURE + "/.BandedFiveActivity": ("ccaa22", "ffdd55", "ffffaa"),
}

COMPONENTS = {
    "cancel": FIXTURE + "/.LaunchActivity",
    "removed": FIXTURE + "/.PermissionActivity",
    "transfer_1": FIXTURE + "/.PaletteOneActivity",
    "transfer_2": FIXTURE + "/.PaletteTwoActivity",
    "transfer_3": FIXTURE + "/.BandedOneActivity",
    "selected_removed": FIXTURE + "/.BandedTwoActivity",
    "same_slot": FIXTURE + "/.BandedThreeActivity",
    "screenshot": FIXTURE + "/.BandedFourActivity",
    "split_primary": FIXTURE + "/.BandedFiveActivity",
    "split_secondary": FIXTURE + "/.PermissionActivity",
    # Reuse the independently proven Screenshot task for the post-stop menu.
    # The active split pair is commonly represented as a grouped Recents card
    # and is therefore deliberately not the unavailable-session probe.
    "unavailable": FIXTURE + "/.BandedFourActivity",
}

LABELS = {
    COMPONENTS["cancel"]: "Wonad picker launch fixture",
    COMPONENTS["removed"]: "Wonad runtime permission fixture",
    COMPONENTS["transfer_1"]: "Wonad Linux palette one",
    COMPONENTS["transfer_2"]: "Wonad Linux palette two",
    COMPONENTS["transfer_3"]: "Wonad Linux banded one",
    COMPONENTS["selected_removed"]: "Wonad Linux banded two",
    COMPONENTS["same_slot"]: "Wonad Linux banded three",
    COMPONENTS["screenshot"]: "Wonad Linux banded four",
    COMPONENTS["split_primary"]: "Wonad Linux banded five",
}

# The seven normal palette subclasses set their actual TaskDescription label
# to javaClass.name. Launcher icons retain their unchanged Manifest labels.
# Only the two unmodified legacy baselines still use the OS package fallback.
PALETTE_COMPONENTS = tuple(FIXTURE + "/." + name for name in (
    "PaletteOneActivity", "PaletteTwoActivity", "BandedOneActivity",
    "BandedTwoActivity", "BandedThreeActivity", "BandedFourActivity", "BandedFiveActivity"))
TASK_TITLES = {component: component.replace("/.", ".") for component in PALETTE_COMPONENTS}
TASK_TITLES.update({FIXTURE + "/." + name: FIXTURE for name in ("OneActivity", "TwoActivity")})
RECENTS_LABELS = {**LABELS, **{component: TASK_TITLES[component] for component in PALETTE_COMPONENTS}}

STAGES = (
    "baseline",
    "cancel_menu", "cancelled",
    "task_remove_card", "task_removed",
    "transfer_1_menu", "transfer_1_done",
    "transfer_2_menu", "transfer_2_done",
    "transfer_3_menu", "transfer_3_done",
    "selected_display_menu", "selected_display_removed", "selected_display_rejected",
    "same_slot_menu", "same_slot_removed", "same_slot_readded", "same_slot_rejected",
    "screenshot_menu", "screenshot_activated",
    "split_menu", "split_select", "split_activated",
    "unavailable",
)

CAPTURE_KINDS = (
    "activities", "fixture", "windows", "input", "display", "conformance",
    "systemui", "log", "hierarchy",
)

SELECTION_STAGES = frozenset({
    "cancel_menu", "transfer_1_menu", "transfer_2_menu", "transfer_3_menu",
    "selected_display_menu", "same_slot_menu", "screenshot_menu", "split_menu",
    "unavailable",
})

LAUNCH_PLAN = {
    "cancel_menu": (COMPONENTS["cancel"],),
    "task_remove_card": (COMPONENTS["removed"],),
    "transfer_1_menu": (COMPONENTS["transfer_1"],),
    "transfer_2_menu": (COMPONENTS["transfer_2"],),
    "transfer_3_menu": (COMPONENTS["transfer_3"],),
    "selected_display_menu": (COMPONENTS["selected_removed"],),
    "same_slot_menu": (COMPONENTS["same_slot"],),
    "screenshot_menu": (COMPONENTS["screenshot"],),
    "split_menu": (COMPONENTS["split_primary"], COMPONENTS["split_secondary"]),
}

# Captures made while genuine Launcher/Recents or the SystemUI screenshot
# surface is visible must preserve the broker's deliberate interaction block.
# Asking the runtime to acknowledge a checkpoint in these states would either
# deadlock the producer or weaken the protected-phone-UI contract.
BLOCKED_STAGES = frozenset({
    "cancel_menu", "cancelled", "task_remove_card", "task_removed",
    "transfer_1_menu", "transfer_2_menu", "transfer_3_menu",
    "selected_display_menu", "selected_display_removed",
    "same_slot_menu", "same_slot_removed", "same_slot_readded",
    "screenshot_menu", "screenshot_activated", "split_menu", "split_select",
})

SETTLED_PHASES = {
    "baseline": "checkpoint",
    "transfer_1_done": "checkpoint",
    "transfer_2_done": "checkpoint",
    "transfer_3_done": "checkpoint",
    "selected_display_rejected": "checkpoint",
    "same_slot_rejected": "checkpoint",
    "split_activated": "checkpoint",
}

EXTERNAL_SURVIVOR_LIFETIMES = {
    # Inclusive stage ranges.  These are the exact native tasks whose broker
    # rows must remain backed by live Android windows until their connector is
    # deliberately removed (or the runtime is deliberately stopped).
    FIXTURE + "/.OneActivity": ("baseline", "split_activated"),
    FIXTURE + "/.TwoActivity": ("baseline", "selected_display_menu"),
    COMPONENTS["transfer_1"]: ("transfer_1_done", "split_activated"),
    COMPONENTS["transfer_2"]: ("transfer_2_done", "selected_display_menu"),
    COMPONENTS["transfer_3"]: ("transfer_3_done", "same_slot_menu"),
}


def external_survivors(name: str) -> tuple[str, ...]:
    ordinal = STAGES.index(name)
    return tuple(component for component, (first, last) in EXTERNAL_SURVIVOR_LIFETIMES.items()
                 if STAGES.index(first) <= ordinal <= STAGES.index(last))


PIXEL_EXPECTATIONS = {
    name: external_survivors(name) + ((COMPONENTS["split_primary"],
                                      COMPONENTS["split_secondary"])
                                     if name == "split_activated" else ())
    for name in STAGES if external_survivors(name) or name == "split_activated"
}


class EvidenceError(ValueError):
    """Evidence is missing, ambiguous, internally inconsistent or unsafe."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate JSON field: " + key)
        value[key] = item
    return value


def stable_bytes(path: Path, maximum: int = 128 * 1024 * 1024) -> bytes:
    require(path.is_absolute(), "Evidence path must be absolute")
    try:
        before = path.lstat()
    except OSError as error:
        raise EvidenceError("Missing evidence file: " + str(path)) from error
    require(stat.S_ISREG(before.st_mode) and not path.is_symlink() and
            0 < before.st_size <= maximum, "Invalid evidence file: " + str(path))
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    after = path.lstat()
    require(len(payload) <= maximum and
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
             before.st_ctime_ns) ==
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
             after.st_ctime_ns), "Evidence changed while being read: " + str(path))
    return payload


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(stable_bytes(path))


def sha256sum_output(raw: str, paths: list[str]) -> dict[str, str]:
    rows = re.findall(r"^([0-9a-f]{64})  (\S+)$", raw, re.M)
    require(len(rows) == len(paths) and [path for _, path in rows] == paths and
            len({path for _, path in rows}) == len(paths),
            "Malformed/ambiguous SHA-256 observation")
    return {path: digest for digest, path in rows}


def active_system_package_path(raw: str, package: str) -> str:
    expected = PRIVILEGED_SYSTEM_PACKAGES.get(package)
    require(expected is not None and raw.splitlines() == ["package:" + expected],
            "Running privileged package is not the immutable candidate system package: " + package)
    return expected


def load_json(path: Path):
    try:
        return json.loads(stable_bytes(path).decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError("Malformed JSON: " + str(path)) from error


def safe_relative(value, label="evidence") -> PurePosixPath:
    require(isinstance(value, str) and value and "\x00" not in value, "Invalid " + label + " path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and value == path.as_posix() and
            all(part not in ("", ".", "..") for part in path.parts),
            "Unsafe " + label + " path")
    return path


def literal_child(root: Path, relative: str) -> Path:
    current = root
    for index, part in enumerate(safe_relative(relative).parts):
        current /= part
        try:
            status = current.lstat()
        except OSError as error:
            raise EvidenceError("Missing sealed evidence: " + relative) from error
        require(not stat.S_ISLNK(status.st_mode), "Sealed evidence traverses a symlink: " + relative)
        require(stat.S_ISDIR(status.st_mode) if index + 1 < len(safe_relative(relative).parts)
                else stat.S_ISREG(status.st_mode), "Wrong sealed evidence type: " + relative)
    return current


def file_ref(path: Path) -> dict:
    payload = stable_bytes(path)
    return {"sha256": sha256_bytes(payload), "bytes": len(payload)}


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def candidate_manifest(raw: str, fingerprint: str) -> dict:
    """Parse the exact unqualified candidate identity used by this lane."""
    try:
        value = json.loads(raw, object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed conformance candidate manifest") from error
    required = {"schema", "kind", "scope", "architecture", "api", "fingerprint", "files",
        "product_images", "os_artifacts", "base_product_candidate", "packet", "artifacts",
        "conformance_version_update", "update_data_canary", "systemui_fault_identity",
        "planned_runtime_gates", "runtime_qualified", "guests_started", "hardware",
        "unofficial", "production_identity", "product_apk_present"}
    require(isinstance(value, dict) and set(value) == required and value["schema"] == 1 and
            value["kind"] == "phase1_fresh_guest_conformance_candidate_v1" and
            value["scope"] == "unqualified_phase1_fresh_guest_os_contract_conformance_candidate" and
            value["architecture"] == "amd64" and value["api"] == 3 and
            value["fingerprint"] == fingerprint and value["runtime_qualified"] is False and
            value["guests_started"] is False and value["hardware"] == "emulator_only" and
            value["unofficial"] is True and value["production_identity"] is False and
            value["product_apk_present"] is False and
            isinstance(value["files"], dict) and
            isinstance(value["product_images"], dict) and
            set(value["product_images"]) == PRODUCT_IMAGES and
            all(SHA256.fullmatch(str(digest)) for digest in value["product_images"].values()) and
            isinstance(value["artifacts"], dict) and
            set(value["artifacts"]) == {"wonad", "conformance", "fixture", "fault"} and
            isinstance(value["os_artifacts"], dict) and
            set(value["os_artifacts"]) == set(OS_GUEST_PATHS),
            "Running image is not the exact unqualified conformance candidate")
    artifact_fields = {"sha256", "bytes", "package", "version_code", "version_name",
        "certificate_der_sha256", "signers", "schemes", "debuggable", "test_only",
        "instrumentation_targets", "shared_uid", "privileged_manifest"}
    expected = (
        ("wonad", APP, [], False, None),
        ("conformance", APP, [APP], False, BUNDLED_APKS[APP]),
        ("fixture", FIXTURE, [], True, BUNDLED_APKS[FIXTURE]),
    )
    for role, package, targets, debuggable, bundle_path in expected:
        row = value["artifacts"].get(role)
        require(isinstance(row, dict) and set(row) == artifact_fields and
                SHA256.fullmatch(str(row["sha256"])) and
                SHA256.fullmatch(str(row["certificate_der_sha256"])) and
                type(row["bytes"]) is int and row["bytes"] > 0 and
                row["package"] == package and type(row["version_code"]) is int and
                row["version_code"] > 0 and isinstance(row["version_name"], str) and
                row["version_name"] and row["signers"] == 1 and
                isinstance(row["schemes"], dict) and row["schemes"].get("3") is True and
                all(isinstance(name, str) and type(enabled) is bool
                    for name, enabled in row["schemes"].items()) and
                row["debuggable"] is debuggable and
                row["test_only"] is False and row["instrumentation_targets"] == targets and
                row["shared_uid"] is False and row["privileged_manifest"] is False and
                (bundle_path is None or value["files"].get(bundle_path) == row["sha256"]),
                "Candidate APK package/version/signer identity changed: " + role)
    require(value["artifacts"]["wonad"]["certificate_der_sha256"] ==
                value["artifacts"]["conformance"]["certificate_der_sha256"] and
            value["artifacts"]["fixture"]["certificate_der_sha256"] !=
                value["artifacts"]["conformance"]["certificate_der_sha256"],
            "Candidate client/fixture signer relationship changed")
    require(all(SHA256.fullmatch(str(value["os_artifacts"][role]))
                for role in OS_GUEST_PATHS),
            "Candidate OS artifact identity is malformed")
    return value


def tree(xml: str) -> ET.Element:
    require(isinstance(xml, str) and "<!DOCTYPE" not in xml and "<!ENTITY" not in xml,
            "Untrusted Launcher hierarchy encoding")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as error:
        raise EvidenceError("Malformed Launcher hierarchy") from error
    require(root.tag in ("hierarchy", "displays"), "Unexpected Launcher hierarchy root")
    return root


def rectangle(node: ET.Element) -> tuple[int, int, int, int]:
    match = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds", ""))
    require(match is not None, "Missing exact phone control bounds")
    left, top, right, bottom = map(int, match.groups())
    require(0 <= left < right <= 1080 and 0 <= top < bottom <= 2400,
            "Launcher control is outside the phone viewport")
    return left, top, right, bottom


def center(box) -> list[int]:
    left, top, right, bottom = box
    return [(left + right) // 2, (top + bottom) // 2]


def launcher_control(xml: str, text: str, *, required=True) -> list[int] | None:
    root = tree(xml)
    parents = {child: parent for parent in root.iter() for child in parent}
    nodes = [node for node in root.iter("node")
             if node.get("package") == LAUNCHER and
             node.get("resource-id") == LAUNCHER + ":id/text" and
             node.get("text") == text and node.get("enabled") == "true"]
    require(len(nodes) <= 1 and (not required or len(nodes) == 1),
            "Missing/ambiguous genuine Launcher control: " + text)
    if not nodes:
        return None
    node = nodes[0]
    parent = parents.get(node)
    require(parent is not None and parent.get("package") == LAUNCHER and
            parent.get("class") == "android.widget.LinearLayout" and
            parent.get("clickable") == "true" and parent.get("enabled") == "true",
            "Launcher action label is not inside its genuine clickable menu row")
    point = center(rectangle(node))
    box = rectangle(parent)
    require(box[0] <= point[0] < box[2] and box[1] <= point[1] < box[3],
            "Launcher action label escapes its clickable menu row")
    return point


def launcher_icon(xml: str, label: str) -> list[int]:
    root = tree(xml)
    parents = {child: parent for parent in root.iter() for child in parent}
    views = [node for node in root.iter("node") if node.get("package") == LAUNCHER and
             node.get("resource-id") == LAUNCHER + ":id/apps_view" and
             node.get("enabled") == "true"]
    lists = [node for node in root.iter("node") if node.get("package") == LAUNCHER and
             node.get("resource-id") == LAUNCHER + ":id/apps_list_view" and
             node.get("enabled") == "true"]
    require(len(views) == len(lists) == 1, "Missing genuine Launcher All Apps ancestry")
    nodes = [node for node in root.iter("node") if node.get("package") == LAUNCHER and
             node.get("resource-id") == LAUNCHER + ":id/icon" and
             node.get("class") == "android.widget.TextView" and
             node.get("text") == label and node.get("content-desc") == label and
             node.get("enabled") == "true" and node.get("clickable") == "true"]
    require(len(nodes) == 1, "Missing/ambiguous ordinary Launcher icon: " + label)
    ancestors = []
    item = nodes[0]
    while item in parents:
        item = parents[item]
        ancestors.append(item)
    require(lists[0] in ancestors and views[0] in ancestors,
            "Launcher icon is outside genuine All Apps")
    return center(rectangle(nodes[0]))


PHONE_HOME_COMPONENT = LAUNCHER + "/.uioverrides.QuickstepLauncher"
PHONE_HOME_WINDOW = LAUNCHER + "/" + LAUNCHER + ".uioverrides.QuickstepLauncher"
PHONE_HOME_RESOLVE = ("cmd", "package", "resolve-activity", "--components", "--user", "0",
                      "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME")
PHONE_TIS_COMPONENT = LAUNCHER + "/com.android.quickstep.TouchInteractionService"
PHONE_TIS_DUMP = ("dumpsys", "activity", "service", PHONE_TIS_COMPONENT)
PHONE_OVERVIEW_LOG = ("logcat", "-b", "main", "-d", "-v", "epoch", "-t", "512",
                      "TISBinder:D", "OverviewCommandHelper:D", "*:S")
PHONE_OVERVIEW_ATTEMPTS = 8
PHONE_OVERVIEW_TIMEOUT_NS = 90_000_000_000


def phone_home_workspace(xml: str) -> list[int]:
    """Derive a normal Home blank-workspace point, never an icon/control tap."""
    root = tree(xml)
    require(root.tag == "hierarchy" and root.get("rotation") == "0",
            "Phone Home hierarchy is not the upright single-display viewport")
    parents = {child: parent for parent in root.iter() for child in parent}
    def nodes(resource):
        return [node for node in root.iter("node") if node.get("package") == LAUNCHER and
                node.get("resource-id") == LAUNCHER + ":id/" + resource and
                node.get("enabled") == "true"]
    workspace, drag, home = nodes("workspace"), nodes("drag_layer"), nodes("accessibility_action_view")
    require(len(workspace) == len(drag) == len(home) == 1 and
            workspace[0].get("class") == "android.widget.ScrollView" and
            home[0].get("content-desc") == "Home" and
            parents.get(workspace[0]) is drag[0] and parents.get(home[0]) is drag[0],
            "Missing/ambiguous normal phone Home workspace ancestry")
    require(not any(nodes(name) for name in ("apps_view", "apps_list_view", "task_view_single")),
            "Home proof contains All Apps or a Recents task")
    point = center(rectangle(workspace[0]))
    for node in (drag[0], home[0]):
        left, top, right, bottom = rectangle(node)
        require(left < point[0] < right and top < point[1] < bottom,
                "Workspace focus point is outside the normal Home viewport")
    for node in root.iter("node"):
        if node.get("enabled") != "true" or not any(
                node.get(key) == "true" for key in ("clickable", "long-clickable")):
            continue
        left, top, right, bottom = rectangle(node)
        require(not (left <= point[0] < right and top <= point[1] < bottom),
                "Workspace focus point intersects an enabled ordinary UI control")
    return point


def phone_home_focus(activities: str, displays: str, windows: str):
    """Reconstruct actual Home Activity and native global/display-0 window focus."""
    sections = re.findall(r"^Display #0 \(activities from top to bottom\):\n"
                          r"(.*?)(?=^Display #[0-9]+ |\Z)", activities, re.M | re.S)
    require(len(sections) == 1, "Missing/ambiguous phone activity display")
    section = sections[0]
    component = re.escape(PHONE_HOME_COMPONENT)
    record = r"ActivityRecord\{([0-9a-f]+) u0 " + component + r" t([1-9][0-9]*)\}"
    top_rows = re.findall(r"^[ \t]*topResumedActivity=([^\n]*)$", section, re.M)
    require(len(top_rows) == 1, "Phone top-resumed Activity field is missing or ambiguous")
    top_match = re.fullmatch(record, top_rows[0].strip())
    require(top_match is not None, "Phone top-resumed Activity is not the exact user-0 Home")
    top = [top_match.groups()]
    require(re.search(
        r"^[ \t]*\* Task\{[^\n}]*\btype=home\b[^\n}]*\bU=0\b"
        r"[^\n}]*\bvisible=true\b[^\n}]*\bvisibleRequested=true\b", section, re.M),
        "Phone is not showing one top-resumed user-0 Home task")
    blocks = re.findall(r"^[ \t]*\* Hist[ \t]+#\d+: " + record + r"\n(.*?)"
        r"(?=^[ \t]*\* Hist[ \t]+#\d+:|^[ \t]*\* Task\{|\Z)", section, re.M | re.S)
    require(len(blocks) == 1 and blocks[0][:2] == top[0],
            "Home ActivityRecord/task identity is ambiguous")
    block = blocks[0][2]
    for pattern in (r"mActivityComponent=" + component,
                    r"state=RESUMED finishing=false", r"mActivityType=home",
                    r"mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true",
                    r"nowVisible=true lastVisibleTime=\S+"):
        require(re.search(r"^[ \t]*" + pattern + r"[ \t]*$", block, re.M),
                "Home Activity is not resumed, drawn and fully visible")
    resumed_rows = re.findall(r"^[ \t]*ResumedActivity:([^\n]*)$", activities, re.M)
    require(len(resumed_rows) == 1, "Global resumed Activity field is missing or ambiguous")
    resumed_match = re.fullmatch(record, resumed_rows[0].strip())
    require(resumed_match is not None and [resumed_match.groups()] == top,
            "Phone Home is not the globally resumed Activity")
    require(re.findall(r"^[ \t]*mTopFocusedDisplayId=(\d+)[ \t]*$", windows, re.M) == ["0"],
            "Native global focus is not uniquely phone display 0")
    display_sections = re.findall(r"^[ \t]*Display: mDisplayId=0(?: \([^\n]*\))?\n"
                                 r"(.*?)(?=^[ \t]*Display: mDisplayId=[0-9]+|\Z)",
                                 displays, re.M | re.S)
    require(len(display_sections) == 1, "Missing/ambiguous native display-0 focus section")
    focus_rows = re.findall(r"^[ \t]*mCurrentFocus=([^\n]*)$", display_sections[0], re.M)
    app_rows = re.findall(r"^[ \t]*mFocusedApp=([^\n]*)$", display_sections[0], re.M)
    require(len(focus_rows) == len(app_rows) == 1,
            "Native phone focus/app fields are missing or ambiguous")
    focus_match = re.fullmatch(r"Window\{([0-9a-f]+) u0 " + re.escape(PHONE_HOME_WINDOW) + r"\}",
                              focus_rows[0].strip())
    app_match = re.fullmatch(record, app_rows[0].strip())
    require(focus_match is not None and app_match is not None and [app_match.groups()] == top,
            "Native phone focus is not the exact Home Activity/window")
    focused = [focus_match[1]]
    live = re.findall(r"^[ \t]*(?:Window #\d+|#\d+) Window\{" + focused[0] + r" u0 " +
                      re.escape(PHONE_HOME_WINDOW) + r"\}:\n(.*?)"
                      r"(?=^[ \t]*(?:Window #\d+|#\d+) Window\{|\Z)", windows, re.M | re.S)
    require(len(live) == 1 and re.search(r"^[ \t]*mDisplayId=0\b", live[0], re.M) and
            re.search(r"\bmHasSurface=true\b", live[0]) and
            re.search(r"^[ \t]*isOnScreen=true[ \t]*$", live[0], re.M) and
            re.search(r"^[ \t]*isVisible=true[ \t]*$", live[0], re.M),
            "Focused Home window is not surfaced and visible on display 0")


def phone_tis_state(raw: str) -> dict:
    """Parse the exact source-defined Quickstep state used to route Overview.

    This is diagnostic evidence, not a claim that Quickstep's asynchronously
    maintained focus must equal WindowManager's display-0 focus.  In
    particular, a foreign or stale non-negative focused display is retained
    verbatim so a failed run can distinguish routing from UI-settle failures.
    """
    headers = re.findall(
        r"^SERVICE " + re.escape(PHONE_TIS_COMPONENT) +
        r" ([0-9a-f]+) pid=([1-9][0-9]*) user=0[ \t]*$", raw, re.M)
    require(len(headers) == 1 and len(re.findall(r"^SERVICE [^\n]+$", raw, re.M)) == 1 and
            len(re.findall(r"^[ \t]*Client:[ \t]*$", raw, re.M)) == 1,
            "Missing/ambiguous exact user-0 TouchInteractionService dump")
    overview = re.findall(r"^[ \t]*OverviewCommandHelper:[ \t]*$", raw, re.M)
    pending = re.findall(r"^[ \t]*pendingCommands=([0-9]+)[ \t]*$", raw, re.M)
    pending_type = re.findall(r"^[ \t]*pendingCommandType=([A-Z_]+)[ \t]*$", raw, re.M)
    keyboard = re.findall(r"^[ \t]*keyboardFocusTask=(\S(?:[^\n]*\S)?)[ \t]*$", raw, re.M)
    require(len(overview) == len(pending) == len(keyboard) == 1 and keyboard[0] and
            0 <= int(pending[0]) <= 3,
            "Malformed/ambiguous source-defined OverviewCommandHelper state")
    command_types = {"SHOW_ALT_TAB", "HIDE_ALT_TAB", "TOGGLE", "HOME",
                     "TOGGLE_OVERVIEW_PREVIOUS", "TOGGLE_WITH_FOCUS"}
    count = int(pending[0])
    require((count == 0 and not pending_type) or
            (count > 0 and len(pending_type) == 1 and pending_type[0] in command_types),
            "Overview command queue/type state is inconsistent")
    touch_ids = [int(value) for value in re.findall(
        r"^[ \t]*TouchState \(displayId ([0-9]+)\):[ \t]*$", raw, re.M)]
    require(touch_ids and 0 in touch_ids and len(touch_ids) == len(set(touch_ids)),
            "TouchInteractionService lacks unique phone input state")
    require(len(re.findall(r"^[ \t]*SystemUiProxy:[ \t]*$", raw, re.M)) == 1,
            "Missing/ambiguous SystemUiProxy state")
    focus = re.findall(
        r"^[ \t]*mFocusState=\{FocusState focusedDisplayId=([0-9]+)\}[ \t]*$", raw, re.M)
    require(len(focus) == 1, "Missing/ambiguous Quickstep focused-display state")
    return {"pid": int(headers[0][1]), "pending_commands": count,
            "pending_command_type": pending_type[0] if pending_type else None,
            "keyboard_focus_task": keyboard[0].strip(),
            "touch_display_ids": touch_ids, "focused_display_id": int(focus[0])}


def phone_overview(xml: str):
    """Require actual visible TaskView/snapshot ancestry, not Home's actions bar."""
    root = tree(xml)
    require(root.tag == "hierarchy" and root.get("rotation") == "0",
            "Overview is not the upright single-display phone hierarchy")
    panels = [node for node in root.iter("node") if node.get("package") == LAUNCHER and
              node.get("resource-id") == LAUNCHER + ":id/overview_panel" and
              node.get("enabled") == "true"]
    require(len(panels) == 1, "Missing/ambiguous genuine Overview panel")
    rectangle(panels[0])
    require(not any(node.get("package") == LAUNCHER and node.get("enabled") == "true" and
        (node.get("resource-id") in {LAUNCHER + ":id/apps_view", LAUNCHER + ":id/apps_list_view"} or
         node.get("resource-id") == LAUNCHER + ":id/accessibility_action_view" and
         node.get("content-desc") == "Home") for node in root.iter("node")),
        "Overview observation still exposes normal Home or All Apps")
    cards = [node for node in panels[0].iter("node") if node.get("package") == LAUNCHER and
             node.get("resource-id") == LAUNCHER + ":id/task_view_single" and
             node.get("enabled") == "true" and node.get("clickable") == "true"]
    require(cards, "Overview contains no genuine visible TaskView")
    for card in cards:
        snapshots = [node for node in card.iter("node") if node.get("package") == LAUNCHER and
            node.get("resource-id") == LAUNCHER + ":id/snapshot" and node.get("enabled") == "true" and
            node.get("content-desc")]
        require(len(snapshots) == 1, "Overview TaskView lacks one labelled snapshot")
        rectangle(snapshots[0])
    return True


def phone_overview_evidence_paths(evidence: dict) -> set[str]:
    """Exact bounded variable retry inventory; no arbitrary new evidence aliases."""
    result = set()
    for stage in (*SELECTION_STAGES, "task_remove_card"):
        prefix = "phone-overview/" + stage + "/"
        paths = {path for path in evidence if path.startswith(prefix)}
        expected = {prefix + "resolve.txt", *(prefix + moment + "-" + kind + ".txt"
                    for moment in ("before", "after-switch")
                    for kind in ("activities", "displays", "windows")),
                    prefix + "before-tis.txt", prefix + "after-switch-tis.txt"}
        for family in ("home", "focus", "overview"):
            pattern = (r"focus-(\d{2})-activities\.txt" if family == "focus" else
                       family + r"-(\d{2})\.xml")
            matches = sorted(int(match[1]) for path in paths
                if (match := re.fullmatch(re.escape(prefix) + pattern, path)))
            require(matches == list(range(len(matches))) and 1 <= len(matches) <= PHONE_OVERVIEW_ATTEMPTS,
                    "Phone Overview evidence has missing or unbounded retries")
            for index in matches:
                expected.update({prefix + "focus-%02d-%s.txt" % (index, kind)
                                 for kind in ("activities", "displays", "windows")} if family == "focus" else
                                {prefix + "%s-%02d.xml" % (family, index)})
        require(paths == expected, "Phone Overview evidence has an undeclared alias or missing raw observation")
        result.update(expected)
    require({path for path in evidence if path.startswith("phone-overview/")} == result,
            "Phone Overview evidence names an unreviewed stage")
    return result


def recents_card(xml: str, label: str, *, chip=True) -> tuple[list[int], tuple[int, int, int, int]]:
    matches = []
    for card in tree(xml).iter("node"):
        if card.get("package") != LAUNCHER or \
                card.get("resource-id") != LAUNCHER + ":id/task_view_single" or \
                card.get("enabled") != "true" or card.get("clickable") != "true":
            continue
        snapshots = [node for node in card.iter("node") if node.get("package") == LAUNCHER and
                     node.get("resource-id") == LAUNCHER + ":id/snapshot" and
                     node.get("enabled") == "true" and label in node.get("content-desc", "")]
        if len(snapshots) != 1:
            continue
        snapshot = rectangle(snapshots[0])
        if chip:
            icons = [node for node in card.iter("node") if node.get("package") == LAUNCHER and
                     node.get("resource-id") == LAUNCHER + ":id/icon" and
                     node.get("enabled") == "true"]
            require(len(icons) == 1, "Recents card lacks its genuine app chip")
            point = center(rectangle(icons[0]))
        else:
            point = center(snapshot)
        matches.append((point, snapshot))
    require(len(matches) == 1, "Missing/ambiguous exact Recents task card: " + label)
    return matches[0]


def conformance_status(raw: str) -> dict:
    marker = "WONAD_CONFORMANCE_STATUS "
    rows = [line.split(marker, 1)[1] for line in raw.splitlines() if marker in line]
    require(len(rows) == 1, "Missing/ambiguous conformance status marker")
    try:
        value = json.loads(rows[0], object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed conformance status") from error
    require(isinstance(value, dict) and value.get("schema") == 1 and
            value.get("state") in ("idle", "running", "passed", "failed") and
            isinstance(value.get("phase"), str), "Invalid conformance status")
    if value["state"] == "idle":
        require(value == {"schema": 1, "state": "idle", "phase": "idle"},
                "Idle conformance status carries untrusted retained state")
        return value
    fields = {"schema", "run", "mode", "state", "phase", "started_elapsed_ms",
              "updated_elapsed_ms", "api_version", "capabilities", "generation",
              "display_ids", "heartbeat_count", "operations", "callbacks", "facades",
              "failure"}
    require(set(value) == fields and RUN_ID.fullmatch(str(value["run"])) is not None and
            value["mode"] == "full" and
            re.fullmatch(r"[a-z0-9-]{1,64}", value["phase"]) is not None and
            type(value["started_elapsed_ms"]) is int and value["started_elapsed_ms"] > 0 and
            type(value["updated_elapsed_ms"]) is int and
            value["updated_elapsed_ms"] >= value["started_elapsed_ms"] and
            value["api_version"] == 3 and type(value["capabilities"]) is int and
            value["capabilities"] > 0 and type(value["generation"]) is int and
            value["generation"] > 0 and isinstance(value["display_ids"], list) and
            value["display_ids"] and all(type(item) is int and item > 0 for item in value["display_ids"]) and
            len(set(value["display_ids"])) == len(value["display_ids"]) and
            type(value["heartbeat_count"]) is int and value["heartbeat_count"] > 0 and
            isinstance(value["operations"], list) and value["operations"] and
            all(isinstance(item, str) and item for item in value["operations"]) and
            len(set(value["operations"])) == len(value["operations"]) and
            isinstance(value["callbacks"], dict) and value["callbacks"] and
            all(isinstance(name, str) and name and type(count) is int and count >= 0
                for name, count in value["callbacks"].items()) and
            any(count > 0 for count in value["callbacks"].values()) and
            isinstance(value["facades"], list) and
            all(isinstance(item, str) and item in {
                "ExternalHomeActivity:valid", "ExternalHomeActivity:rejected",
                "ExternalShellActivity:valid", "ExternalShellActivity:rejected",
                "LauncherActivity:valid", "LauncherActivity:rejected"} for item in value["facades"]) and
            "ExternalHomeActivity:valid" in value["facades"] and
            "ExternalShellActivity:valid" in value["facades"] and
            ((value["state"] == "failed" and isinstance(value["failure"], str) and value["failure"]) or
             (value["state"] != "failed" and value["failure"] is None)),
            "Malformed full conformance session ledger")
    return value


def runtime_status(raw: str) -> dict:
    """Parse the bounded long-lived policy-free client journal independently."""
    marker = "WONAD_CONFORMANCE_STATUS "
    rows = [line.split(marker, 1)[1] for line in raw.splitlines() if marker in line]
    require(len(rows) == 1, "Missing/ambiguous conformance runtime status marker")
    try:
        value = json.loads(rows[0], object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed conformance runtime status") from error
    fields = {
        "schema", "kind", "run", "mode", "state", "phase", "started_elapsed_ms",
        "updated_elapsed_ms", "api_version", "capabilities", "one_shot_api_coverage",
        "runtime_readiness", "revocation_reason", "heartbeat_count", "handshake",
        "snapshot", "callbacks", "facades", "failure", "control_error",
    }
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == 1 and
            value["kind"] == "policy_free_conformance_runtime_v1" and
            value["mode"] == "runtime" and RUN_ID.fullmatch(str(value["run"])) is not None and
            value["state"] in {"running", "ready", "waiting-reopen", "stopped", "failed"} and
            re.fullmatch(r"[a-z0-9-]{1,64}", str(value["phase"])) is not None and
            type(value["started_elapsed_ms"]) is int and value["started_elapsed_ms"] >= 0 and
            type(value["updated_elapsed_ms"]) is int and
            value["updated_elapsed_ms"] >= value["started_elapsed_ms"] and
            value["api_version"] in (0, 3) and type(value["capabilities"]) is int and
            0 <= value["capabilities"] <= 2**63 - 1 and
            value["one_shot_api_coverage"] == {"mode": "full", "status": "not_run"} and
            type(value["heartbeat_count"]) is int and 0 <= value["heartbeat_count"] <= 2**63 - 1 and
            (value["revocation_reason"] is None or type(value["revocation_reason"]) is int) and
            (value["failure"] is None or isinstance(value["failure"], str) and
             0 < len(value["failure"]) <= 1024) and
            (value["control_error"] is None or isinstance(value["control_error"], str) and
             0 < len(value["control_error"]) <= 512),
            "Malformed policy-free runtime status")
    readiness = value["runtime_readiness"]
    handshake = value["handshake"]
    require(isinstance(readiness, dict) and set(readiness) == {"ready", "session_open", "reopen_required"} and
            all(type(readiness[name]) is bool for name in readiness) and
            isinstance(handshake, dict) and set(handshake) == {"nonce", "phase", "result"} and
            RUN_ID.fullmatch(str(handshake["nonce"])) is not None and
            handshake["phase"] in {"start", "checkpoint", "copy-observed", "reopen", "stop"} and
            handshake["result"] in {"pending", "accepted", "rejected"},
            "Malformed runtime readiness/handshake")
    callbacks = value["callbacks"]
    require(isinstance(callbacks, dict) and set(callbacks) ==
            {"onSnapshot", "onCommand", "onResult", "onRevoked"} and
            all(type(count) is int and 0 <= count <= 2**63 - 1 for count in callbacks.values()) and
            isinstance(value["facades"], list) and len(value["facades"]) <= 64 and
            all(item in {"ExternalHomeActivity:valid", "ExternalHomeActivity:rejected",
                         "ExternalShellActivity:valid", "ExternalShellActivity:rejected",
                         "LauncherActivity:valid", "LauncherActivity:rejected"}
                for item in value["facades"]),
            "Malformed runtime callback/facade journal")
    snapshot = value["snapshot"]
    if snapshot is not None:
        require(isinstance(snapshot, dict) and set(snapshot) == {
            "generation", "revision", "topology_revision", "identity_epoch",
            "focused_display_token", "focused_token", "interaction_blocked",
            "display_incarnations", "tasks"}, "Malformed runtime snapshot fields")
        require(all(type(snapshot[name]) is int and snapshot[name] > 0 for name in
                    ("generation", "revision", "topology_revision", "identity_epoch")) and
                type(snapshot["focused_display_token"]) is int and
                type(snapshot["focused_token"]) is int and
                type(snapshot["interaction_blocked"]) is bool and
                isinstance(snapshot["display_incarnations"], list) and
                1 <= len(snapshot["display_incarnations"]) <= 9 and
                isinstance(snapshot["tasks"], list) and len(snapshot["tasks"]) <= 128,
                "Malformed/unbounded runtime snapshot")

        def valid_bounds(bounds):
            return isinstance(bounds, list) and len(bounds) == 4 and \
                all(type(item) is int and -32768 <= item <= 32768 for item in bounds) and \
                bounds[0] < bounds[2] and bounds[1] < bounds[3]

        displays = snapshot["display_incarnations"]
        require(all(isinstance(row, dict) and set(row) == {
                    "token", "display_id", "identity_hint", "shell_generation",
                    "density_dpi", "bounds"} and
                    all(type(row[name]) is int and row[name] > 0 for name in
                        ("token", "display_id", "identity_hint", "density_dpi")) and
                    type(row["shell_generation"]) is int and
                    row["shell_generation"] in (0, snapshot["generation"]) and
                    valid_bounds(row["bounds"]) for row in displays) and
                [row["token"] for row in displays] == sorted({row["token"] for row in displays}) and
                len({row["display_id"] for row in displays}) == len(displays),
                "Malformed/duplicate runtime display incarnations")
        live_displays = {row["token"] for row in displays}
        tasks = snapshot["tasks"]
        require(all(isinstance(row, dict) and set(row) == {
                    "token", "display_token", "minimum_width", "minimum_height", "resizable",
                    "visible", "input_enabled", "z_order", "title", "package_name", "bounds"} and
                    type(row["token"]) is int and row["token"] > 0 and
                    type(row["display_token"]) is int and row["display_token"] in live_displays and
                    type(row["minimum_width"]) is int and 0 <= row["minimum_width"] <= 2**31 - 1 and
                    type(row["minimum_height"]) is int and 0 <= row["minimum_height"] <= 2**31 - 1 and
                    type(row["resizable"]) is bool and type(row["visible"]) is bool and
                    type(row["input_enabled"]) is bool and row["visible"] is row["input_enabled"] and
                    type(row["z_order"]) is int and isinstance(row["title"], str) and
                    len(row["title"]) <= 160 and isinstance(row["package_name"], str) and
                    0 < len(row["package_name"]) <= 255 and valid_bounds(row["bounds"])
                    for row in tasks) and
                [row["token"] for row in tasks] == sorted({row["token"] for row in tasks}) and
                sorted(row["z_order"] for row in tasks) == list(range(len(tasks))) and
                snapshot["focused_display_token"] in ({0} | live_displays) and
                (snapshot["focused_token"] == 0 or any(row["token"] == snapshot["focused_token"] and
                    row["visible"] for row in tasks)),
                "Malformed/duplicate runtime task snapshot")
    if readiness["ready"]:
        require(value["state"] == "ready" and readiness == {
                    "ready": True, "session_open": True, "reopen_required": False} and
                snapshot is not None and not snapshot["interaction_blocked"] and
                all(row["shell_generation"] == snapshot["generation"]
                    for row in snapshot["display_incarnations"]) and
                value["api_version"] == 3 and value["capabilities"] > 0 and
                value["heartbeat_count"] > 0,
                "Claimed runtime readiness lacks a held fully-shelled session")
    if value["state"] == "running":
        require(readiness == {"ready": False, "session_open": True,
                              "reopen_required": False} and snapshot is not None and
                (snapshot["interaction_blocked"] or any(row["shell_generation"] !=
                    snapshot["generation"] for row in snapshot["display_incarnations"])),
                "Running runtime lacks a bounded blocked/unshelled observation")
    if readiness["reopen_required"]:
        require(value["state"] == "waiting-reopen" and not readiness["ready"] and
                not readiness["session_open"], "Reopen authority escaped final-undock state")
    if value["state"] in {"stopped", "failed"}:
        require(readiness == {"ready": False, "session_open": False, "reopen_required": False},
                "Terminal runtime retains session authority")
    require(value["state"] != "failed" or value["failure"] is not None,
            "Failed runtime status lacks failure identity")
    return value


def inactive_conformance_status(raw: str) -> dict:
    """Accept exact cold-service absence, or an idle/terminal prior worker.

    Pinned ActivityManagerService.dump prints these two lines when this exact
    service does not exist.  This is a host-derived absence observation, not an
    APK status ledger; arbitrary empty/truncated/foreign dumps do not qualify.
    """
    require(isinstance(raw, str), "Malformed prior conformance service dump")
    absent = "No services match: " + APP + "/.ConformanceService\nUse -h for help."
    if raw in (absent, absent + "\n"):
        return {"schema": 1, "state": "absent", "phase": "absent"}
    require("No services match:" not in raw,
            "Ambiguous/foreign/truncated conformance service absence")
    marker = "WONAD_CONFORMANCE_STATUS "
    rows = [line.split(marker, 1)[1] for line in raw.splitlines() if marker in line]
    require(len(rows) == 1, "Missing/ambiguous prior conformance status")
    try:
        value = json.loads(rows[0], object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed prior conformance status") from error
    if value == {"schema": 1, "state": "idle", "phase": "idle"}:
        return value
    if value.get("kind") == "policy_free_conformance_runtime_v1":
        parsed = runtime_status(raw)
        require(parsed["state"] in {"stopped", "failed"}, "Prior runtime is still active")
        return parsed
    parsed = conformance_status(raw)
    require(parsed["state"] in {"passed", "failed"}, "Prior one-shot conformance is still active")
    return parsed


def instrumentation_success(raw: str, run: str):
    require(isinstance(raw, str) and 0 < len(raw.encode()) <= 1024 * 1024 and
            not re.search(r"(?i)(INSTRUMENTATION_FAILED|INSTRUMENTATION_ABORTED|"
                          r"FAILURES!!!|Process crashed|shortMsg\s*=|runtime=failed|"
                          r"instrumentation timeout)", raw),
            "Runtime instrumentation reported a failure/abort")
    required = {
        "INSTRUMENTATION_RESULT: run=" + run,
        "INSTRUMENTATION_RESULT: mode=runtime",
        "INSTRUMENTATION_RESULT: api=3",
        "INSTRUMENTATION_RESULT: runtime=stopped",
        "INSTRUMENTATION_CODE: -1",
    }
    lines = [line.strip() for line in raw.splitlines()]
    require(all(lines.count(marker) == 1 for marker in required) and
            sum(line.startswith("INSTRUMENTATION_CODE:") for line in lines) == 1,
            "Runtime instrumentation lacks its exact terminal success bundle")
    return True


def package_manager_uid_row(raw: str, package: str) -> str:
    """Select one full package identity from a strict substring-query result.

    PackageManager's positional filter is a substring, not an exact-name
    selector. Parse and reject malformed/duplicate rows before selecting the
    requested full name; the original raw query remains in the command trace.
    """
    require(isinstance(raw, str), "Malformed PackageManager UID output")
    lines = raw.splitlines()
    require(lines and raw in ("\n".join(lines), "\n".join(lines) + "\n"),
            "Non-canonical PackageManager UID output")
    result = {}
    for line in lines:
        match = re.fullmatch(
            r"package:([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*) uid:([1-9][0-9]{0,5})",
            line)
        require(match is not None, "Malformed PackageManager UID row")
        name, uid = match.groups()
        require(name not in result and int(uid) < 200000,
                "Duplicate/invalid PackageManager package UID")
        result[name] = line
    require(package in result, "Missing exact PackageManager package UID: " + package)
    return result[package]


def package_uids(raw: str) -> dict:
    result = {}
    lines = raw.splitlines()
    require(raw.endswith("\n") and len(lines) == 4,
            "Incomplete or non-canonical package UID evidence")
    for line in lines:
        match = re.fullmatch(r"package:([^\s]+) uid:(\d+)", line)
        require(match is not None, "Malformed package UID evidence")
        package, uid = match.groups()
        require(package not in result and 0 < int(uid) < 200000, "Ambiguous package UID")
        result[package] = int(uid)
    require(set(result) == {APP, FIXTURE, LAUNCHER, SYSTEMUI}, "Incomplete package UID evidence")
    require(len(set(result.values())) == 4, "Privileged/client/fixture UID alias")
    require(all(FIRST_APPLICATION_UID <= result[package] <= LAST_APPLICATION_UID
                for package in (APP, FIXTURE)),
            "Client/fixture lacks an ordinary application UID for active user 0")
    return result


def package_identity_derivation(trace: list, row: dict, evidence: dict,
                                directory: Path, container: str) -> dict:
    """Replay the exact user-0 forward and singleton reverse UID reads."""
    require(row["evidence"] in evidence and
            row["output_sha256"] == sha256(literal_child(directory, row["evidence"])) and
            isinstance(row["inputs"], list) and len(row["inputs"]) == 6 and
            all(type(index) is int and 0 <= index < row["sequence"] for index in row["inputs"]),
            "Malformed derived package identity evidence")
    packages = (APP, FIXTURE, LAUNCHER, SYSTEMUI)
    source_rows = [trace[index] for index in row["inputs"]]
    expected_commands = [["docker", "exec", container, "adb", "-s", SERIAL,
        "shell", "cmd", "package", "list", "packages", "-U", "--user", "0", package]
        for package in packages]
    lines = []
    for source, expected, package in zip(source_rows[:4], expected_commands, packages):
        require(source.get("argv") == expected and source.get("returncode") == 0 and
                isinstance(source.get("output"), str),
                "Derived UID evidence lacks its exact PackageManager read")
        lines.append(package_manager_uid_row(source["output"], package))
    payload = "\n".join(lines) + "\n"
    uids = package_uids(payload)
    reverse_commands = [["docker", "exec", container, "adb", "-s", SERIAL,
        "shell", "cmd", "package", "list", "packages", "-U", "--user", "0",
        "--uid", str(uids[package])] for package in (APP, FIXTURE)]
    for source, expected, package in zip(source_rows[4:], reverse_commands, (APP, FIXTURE)):
        require(source.get("argv") == expected and source.get("returncode") == 0 and
                source.get("output", "").splitlines() ==
                    ["package:%s uid:%d" % (package, uids[package])],
                "Package UID is shared, cross-user or not reverse-bound")
    identity_prefix = ["docker", "exec", container, "adb", "-s", SERIAL,
                       "shell", "cmd", "package", "list", "packages"]
    identity_rows = {index for index, source in enumerate(trace)
                     if source.get("argv", [])[:len(identity_prefix)] == identity_prefix}
    require(identity_rows == set(row["inputs"]),
            "Unpaired package identity observation exists")
    require(stable_bytes(literal_child(directory, row["evidence"])) == payload.encode(),
            "Derived UID evidence differs from original commands")
    return uids


def fixture_records(raw: str) -> tuple[dict, dict]:
    require("Exception occurred while dumping:" not in raw and
            "Failure while dumping the activity:" not in raw, "Incomplete fixture dump")
    marker_components = {
        "WONAD_OBSERVATION ": {
            FIXTURE + "/.LaunchActivity", FIXTURE + "/.OneActivity",
            FIXTURE + "/.TwoActivity",
        },
        "WONAD_PERMISSION ": {FIXTURE + "/.PermissionActivity"},
        "WONAD_PALETTE ": {
            FIXTURE + "/.PaletteOneActivity", FIXTURE + "/.PaletteTwoActivity",
        },
        "WONAD_BANDED_PALETTE ": {
            FIXTURE + "/.BandedOneActivity", FIXTURE + "/.BandedTwoActivity",
            FIXTURE + "/.BandedThreeActivity", FIXTURE + "/.BandedFourActivity",
            FIXTURE + "/.BandedFiveActivity",
        },
    }
    result = {}
    for line in raw.splitlines():
        markers = [marker for marker in marker_components if marker in line]
        if not markers:
            continue
        require(len(markers) == 1, "Ambiguous fixture observation marker")
        marker = markers[0]
        try:
            row = json.loads(line.split(marker, 1)[1], object_pairs_hook=strict_object)
        except json.JSONDecodeError as error:
            raise EvidenceError("Malformed fixture observation") from error
        component = row.get("component")
        require(component in marker_components[marker] and
                component not in result, "Foreign/duplicate fixture observation")
        for field in ("task", "display"):
            require(type(row.get(field)) is int, "Invalid fixture scalar: " + field)
        if marker == "WONAD_PERMISSION ":
            bounds = row.get("bounds")
            require(row.get("schema") == 1 and isinstance(bounds, list) and len(bounds) == 4 and
                    all(type(value) is int for value in bounds) and
                    type(row.get("uid")) is int and row["uid"] > 0 and
                    type(row.get("key_requests")) is int and row["key_requests"] >= 0 and
                    type(row.get("button_requests")) is int and row["button_requests"] >= 0,
                    "Malformed permission fixture observation")
            row = {**row, "left": bounds[0], "top": bounds[1],
                   "right": bounds[2], "bottom": bounds[3]}
        else:
            for field in ("left", "top", "right", "bottom", "key_downs",
                          "pointer_downs", "mouse_downs"):
                require(type(row.get(field)) is int, "Invalid fixture scalar: " + field)
        require(row["task"] > 0 and row["display"] >= 0 and
                UUID.fullmatch(str(row.get("instance"))) is not None and
                0 < row["right"] - row["left"] <= 4000 and
                0 < row["bottom"] - row["top"] <= 2400,
                "Invalid fixture native lifetime/geometry")
        result[component] = row
    membership = {}
    for task, display in re.findall(r"^TASK [^\n]* id=(\d+) userId=0 displayId=(\d+)\(type=[A-Z_]+\)", raw, re.M):
        task, display = int(task), int(display)
        require(task not in membership, "Duplicate Android task membership")
        membership[task] = display
    for row in result.values():
        require(membership.get(row["task"]) == row["display"],
                "Fixture display disagrees with ActivityTaskManager")
    require(len({row["task"] for row in result.values()}) == len(result) and
            len({row["instance"] for row in result.values()}) == len(result),
            "Fixture tasks share native lifetime")
    return result, membership


def fixture_identities(fixture: str, activities: str, records: dict, uid: int) -> dict:
    primary = re.split(r"^ActivityTaskSupervisor state:\s*$", activities, maxsplit=1,
                       flags=re.M)[0]
    result = {}
    for component, record in records.items():
        header = re.findall(r"^  ACTIVITY " + re.escape(component) +
            r" ([0-9a-f]+) pid=([1-9][0-9]*) userId=0 uid=(\d+) displayId=(\d+)\(type=[A-Z_]+\)$",
            fixture, re.M)
        tasks = re.findall(r"^\s*\* Task\{([0-9a-f]+) #" + str(record["task"]) +
                           r" [^\n]*?\bU=0\b[^\n]*\}", primary, re.M)
        activity = re.findall(r"^\s*\* Hist\s+#\d+: ActivityRecord\{([0-9a-f]+) u0 " +
                              re.escape(component) + r" t" + str(record["task"]) + r"\}",
                              primary, re.M)
        require(len(header) == len(tasks) == len(activity) == 1 and
                int(header[0][1]) > 0 and int(header[0][2]) == uid and
                int(header[0][3]) == record["display"],
                "Fixture UUID is not bound to one exact Task/ActivityRecord/UID")
        result[component] = {"task": record["task"], "instance": record["instance"],
            "binder": header[0][0], "pid": int(header[0][1]), "uid": uid,
            "task_object": tasks[0], "activity_record": activity[0]}
    return result


def logical_displays(raw: str) -> dict[int, dict]:
    rows = re.findall(r"^\s*mBaseDisplayInfo=(DisplayInfo\{[^\n]+)\s*$", raw, re.M)
    require(rows, "Logical display diagnostics unavailable")
    result = {}
    for row in rows:
        fields = [re.search(pattern, row) for pattern in (
            r", displayId (\d+),", r", type ([A-Z_]+),", r', uniqueId "([^"\n]+)"',
            r", real (\d+) x (\d+),", r", density (\d+) \(", r", state ([A-Z_]+),")]
        require(all(fields), "Unrecognized logical display row")
        display = int(fields[0][1])
        if display == 0:
            continue
        flags = set(re.findall(r"\bFLAG_[A-Z_]+\b", row))
        require(display not in result and fields[1][1] == "VIRTUAL" and fields[5][1] == "ON" and
                {"FLAG_TRUSTED", "FLAG_SECURE"} <= flags and
                "FLAG_PRIVATE" not in flags, "Untrusted/ambiguous external display")
        unique = fields[2][1]
        slots = [slot for slot in DISPLAY_SPECS if unique ==
                 "virtual:com.android.emulator.multidisplay:" + str(1234561 + slot)]
        require(len(slots) == 1, "Foreign external display in Recents evidence")
        slot = slots[0]
        size = tuple(map(int, fields[3].groups())) + (int(fields[4][1]),)
        require(size == DISPLAY_SPECS[slot], "External connector geometry/density changed")
        result[display] = {"display": display, "slot": slot, "unique_id": unique,
                           "width": size[0], "height": size[1], "density": size[2],
                           "flags": sorted(flags)}
    require(len({row["slot"] for row in result.values()}) == len(result),
            "Duplicate emulator connector lifetime")
    return result


def focused_display(raw: str) -> int:
    values = re.findall(r"^\s*mTopFocusedDisplayId=(\d+)\s*$", raw, re.M)
    if not values:
        values = re.findall(r"^\s*topFocusedDisplayId=(\d+)\s*$", raw, re.M)
    require(len(values) == 1, "Missing/ambiguous globally focused display")
    return int(values[0])


def authoritative_activity_tree(activities: str) -> str:
    """Select only ATMS' primary display tree, never ATS' repeated summary.

    Pinned ATMS.dumpActivitiesLocked emits the primary tree before ATS.dump,
    which prints its own exact heading and another root/task/Activity summary.
    Keep the original full dump as evidence; scope only this parser's traversal.
    """
    require(type(activities) is str, "Malformed authoritative Activity tree scope")
    lines = activities.splitlines()
    header = "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)"
    boundary = "ActivityTaskSupervisor state:"
    require(lines and lines[0] == header and
            [line for line in lines if header in line] == [header] and
            activities in ("\n".join(lines), "\n".join(lines) + "\n") and
            [line for line in lines if "ActivityTaskSupervisor state" in line] == [boundary],
            "Missing/duplicate/malformed authoritative Activity tree scope")
    sections = activities.split(boundary + "\n")
    require(len(sections) == 2 and sections[1].strip(), "Missing complete authoritative Activity tree boundary")
    headings = [line for line in sections[0].splitlines() if "(activities from top to bottom)" in line]
    matches = [re.fullmatch(r"Display #(0|[1-9][0-9]*) \(activities from top to bottom\):", line) for line in headings]
    require(matches and all(matches) and len({match[1] for match in matches}) == len(matches) and
            all(int(match[1]) <= 2**31 - 1 for match in matches),
            "Missing/duplicate/malformed authoritative Activity display scope")
    return sections[0]


def shell_incarnations(activities: str, windows: str, inputs: str, generation: int,
                       app_uid: int, displays: dict) -> dict[int, dict]:
    result = {}
    # Each shell Activity is in its own task.  Bind the task/ActivityRecord to
    # the URI carrying the broker generation and opaque display token, then to
    # the exact drawn window and dispatcher handle on that logical display.
    sections = re.split(r"(?m)^Display #(\d+) \(activities from top to bottom\):\n", authoritative_activity_tree(activities))
    for section_index in range(1, len(sections), 2):
        display, section = int(sections[section_index]), sections[section_index + 1]
        if display not in displays:
            continue
        for match in re.finditer(r"^\s*\* Task\{([0-9a-f]+) #(\d+) [^\n]*\}\n(?P<body>.*?)(?=^\s*\* Task\{|\Z)",
                                 section, re.M | re.S):
            body = match.group("body")
            activity = re.findall(r"ActivityRecord\{([0-9a-f]+) u0 " + re.escape(APP) +
                                  r"/\.ExternalShellActivity t" + match[2] + r"\}", body)
            uri = re.findall(r"dat=wonad-shell://(\d+)/(\d+)", body)
            if not activity and not uri:
                continue
            require(len(set(activity)) == 1 and len(set(uri)) == 1,
                    "Malformed/ambiguous conformance shell Activity")
            gen, token = map(int, uri[0])
            require(gen == generation and token > 0 and display not in result,
                    "Shell URI/session/display binding changed")
            component = APP + "/" + APP + ".ExternalShellActivity"
            window_rows = []
            for block in re.split(r"(?=^\s*Window #\d+ Window\{)", windows, flags=re.M):
                header = re.match(r"^\s*Window #\d+ Window\{([0-9a-f]+) u0 " +
                                  re.escape(component) + r"\}:?", block)
                if header and re.search(r"\bmDisplayId=" + str(display) + r"\b", block) and \
                        re.search(r"\bmOwnerUid=" + str(app_uid) + r"\b", block) and \
                        "mHasSurface=true" in block and "HAS_DRAWN" in block and \
                        "isOnScreen=true" in block and "isVisible=true" in block and \
                        re.search(r"mActivityRecord=ActivityRecord\{" +
                                  re.escape(activity[0]) + r"\b", block):
                    window_rows.append((header[1], block))
            input_rows = [] if len(window_rows) != 1 else [
                line for line in inputs.splitlines() if component in line and
                re.search(r"\bname=" + re.escape(window_rows[0][0]) + r" " +
                          re.escape(component) + r",", line) and
                re.search(r"\bdisplayId=" + str(display) + r",", line) and
                re.search(r"\bownerUid=" + str(app_uid) + r",", line)]
            require(len(window_rows) == 1 and len(input_rows) == 1 and
                    "SECURE" in window_rows[0][1] and "NOT_FOCUSABLE" in input_rows[0] and
                    "NOT_VISIBLE" not in input_rows[0] and "DROP_INPUT" not in input_rows[0],
                    "Shell incarnation lacks its exact secure drawn window/input handle")
            result[display] = {"slot": displays[display]["slot"], "display": display,
                               "generation": gen, "token": token, "task": int(match[2]),
                               "task_object": match[1], "activity_record": activity[0]}
    require(len({row["token"] for row in result.values()}) == len(result),
            "Conformance shell display token is aliased")
    return result


def home_incarnations(activities: str, windows: str, inputs: str,
                      app_uid: int, displays: dict) -> dict[int, dict]:
    result = {}
    sections = re.split(r"(?=^Display #(\d+) \(activities from top to bottom\):)", authoritative_activity_tree(activities), flags=re.M)
    for index in range(1, len(sections), 2):
        display, body = int(sections[index]), sections[index + 1]
        if display not in displays:
            continue
        activities_found = set(re.findall(r"ActivityRecord\{([0-9a-f]+) u0 " + re.escape(APP) +
                                          r"/\.ExternalHomeActivity t(\d+)\}", body))
        if not activities_found:
            continue
        require(len(activities_found) == 1,
                "External display has ambiguous conformance Home Activities")
        activity = next(iter(activities_found))
        # A secondary HOME normally sits in a root home Task plus a leaf home
        # Task.  Bind the ActivityRecord's task ID to the leaf, rather than
        # incorrectly requiring the root and leaf task records to be identical.
        tasks = set(re.findall(r"\* Task\{([0-9a-f]+) #" + re.escape(activity[1]) +
                               r" [^\n]*\btype=home\b[^\n]*\bU=0\b[^\n]*\}", body))
        require(len(tasks) == 1,
                "External Home ActivityRecord lacks one exact native home Task")
        task_object = next(iter(tasks))
        component = APP + "/" + APP + ".ExternalHomeActivity"
        window_rows = []
        for block in re.split(r"(?=^\s*Window #\d+ Window\{)", windows, flags=re.M):
            header = re.match(r"^\s*Window #\d+ Window\{([0-9a-f]+) u0 " +
                              re.escape(component) + r"\}:?", block)
            if header and re.search(r"\bmDisplayId=" + str(display) + r"\b", block) and \
                    re.search(r"\btaskId=" + re.escape(activity[1]) + r"\b", block) and \
                    re.search(r"\bmOwnerUid=" + str(app_uid) + r"\b", block) and \
                    re.search(r"mActivityRecord=ActivityRecord\{" +
                              re.escape(activity[0]) + r"\b", block) and \
                    "mHasSurface=true" in block and "HAS_DRAWN" in block and "SECURE" in block:
                window_rows.append((header[1], block))
        input_rows = [] if len(window_rows) != 1 else [
            line for line in inputs.splitlines() if component in line and
            re.search(r"\bname=" + re.escape(window_rows[0][0]) + r" " +
                      re.escape(component) + r",", line) and
            re.search(r"\bdisplayId=" + str(display) + r",", line) and
            re.search(r"\bownerUid=" + str(app_uid) + r",", line) and
            not re.search(r"\b(?:NOT_VISIBLE|DROP_INPUT|DROP_INPUT_IF_OBSCURED|PAUSE_DISPATCHING|SPY)\b",
                          line)]
        require(len(window_rows) == len(input_rows) == 1,
                "External Home incarnation lacks its exact secure drawn window/input handle")
        result[display] = {"slot": displays[display]["slot"], "display": display,
                           "task": int(activity[1]), "task_object": task_object,
                           "activity_record": activity[0]}
    return result


def png_info(payload: bytes, regions: dict | None = None) -> dict:
    require(payload.startswith(b"\x89PNG\r\n\x1a\n") and len(payload) >= 45,
            "Framebuffer is not a PNG")
    offset, chunks, ended = 8, [], False
    while offset < len(payload):
        require(offset + 12 <= len(payload), "Truncated framebuffer PNG chunk")
        length = struct.unpack(">I", payload[offset:offset + 4])[0]
        kind = payload[offset + 4:offset + 8]
        end = offset + 12 + length
        require(length <= 64 * 1024 * 1024 and end <= len(payload) and
                re.fullmatch(rb"[A-Za-z]{4}", kind) is not None,
                "Malformed framebuffer PNG chunk")
        data = payload[offset + 8:offset + 8 + length]
        expected_crc = struct.unpack(">I", payload[offset + 8 + length:end])[0]
        require((zlib.crc32(kind + data) & 0xffffffff) == expected_crc,
                "Framebuffer PNG checksum failed")
        chunks.append((kind, data))
        offset = end
        if kind == b"IEND":
            require(length == 0 and offset == len(payload),
                    "Framebuffer PNG has data after IEND")
            ended = True
            break
    require(ended and chunks and chunks[0][0] == b"IHDR" and
            len(chunks[0][1]) == 13 and sum(kind == b"IHDR" for kind, _ in chunks) == 1 and
            any(kind == b"IDAT" and data for kind, data in chunks),
            "Framebuffer lacks canonical IHDR/IDAT/IEND chunks")
    width, height, depth, color, compression, filtering, interlace = struct.unpack(
        ">IIBBBBB", chunks[0][1])
    channels = {0: 1, 2: 3, 4: 2, 6: 4}.get(color)
    require(0 < width <= 4000 and 0 < height <= 2400 and depth == 8 and channels is not None and
            compression == 0 and filtering == 0 and interlace == 0,
            "Framebuffer PNG is not bounded non-interlaced 8-bit pixels")
    row_bytes = width * channels
    expected = height * (row_bytes + 1)
    require(expected <= 64 * 1024 * 1024, "Framebuffer pixels exceed bounded decoder")
    compressed = b"".join(data for kind, data in chunks if kind == b"IDAT")
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(compressed, expected + 1)
        require(not inflater.unconsumed_tail and len(raw) <= expected,
                "Framebuffer expands past declared geometry")
        raw += inflater.flush(expected + 1 - len(raw))
    except zlib.error as error:
        raise EvidenceError("Framebuffer PNG pixels do not inflate") from error
    require(inflater.eof and not inflater.unused_data and len(raw) == expected,
            "Framebuffer PNG pixels do not match declared geometry")

    def paeth(left, above, upper_left):
        estimate = left + above - upper_left
        distances = (abs(estimate - left), abs(estimate - above), abs(estimate - upper_left))
        return (left, above, upper_left)[distances.index(min(distances))]

    rows, cursor, previous = [], 0, bytes(row_bytes)
    for _ in range(height):
        filter_type = raw[cursor]
        encoded = raw[cursor + 1:cursor + 1 + row_bytes]
        cursor += row_bytes + 1
        require(filter_type in range(5), "Unknown framebuffer PNG row filter")
        decoded = bytearray(row_bytes)
        for index, value in enumerate(encoded):
            left = decoded[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            predictor = (0, left, above, (left + above) // 2,
                         paeth(left, above, upper_left))[filter_type]
            decoded[index] = (value + predictor) & 0xff
        previous = bytes(decoded)
        rows.append(previous)
    pixels = bytearray(width * height * 4)
    target = 0
    for row in rows:
        for offset in range(0, len(row), channels):
            if color == 0:
                red = green = blue = row[offset]; alpha = 255
            elif color == 2:
                red, green, blue = row[offset:offset + 3]; alpha = 255
            elif color == 4:
                red = green = blue = row[offset]; alpha = row[offset + 1]
            else:
                red, green, blue, alpha = row[offset:offset + 4]
            pixels[target:target + 4] = bytes((red, green, blue, alpha)); target += 4
    known = {color: 0 for colors in FIXTURE_COLORS.values() for color in colors}
    for offset in range(0, len(pixels), 4):
        key = pixels[offset:offset + 3].hex()
        if key in known and pixels[offset + 3] == 255:
            known[key] += 1
    region_known = {}
    for component, bounds in (regions or {}).items():
        require(component in FIXTURE_COLORS and isinstance(bounds, (list, tuple)) and
                len(bounds) == 4 and all(type(value) is int for value in bounds),
                "Malformed framebuffer task region")
        left, top, right, bottom = bounds
        require(0 <= left < right <= width and 0 <= top < bottom <= height,
                "Framebuffer task region escapes its exact connector")
        counts = {color: 0 for color in FIXTURE_COLORS[component]}
        band_counts = {color: 0 for color in FIXTURE_COLORS[component]}
        band_areas = {color: 0 for color in FIXTURE_COLORS[component]}
        encoded = {bytes.fromhex(color) + b"\xff": color for color in counts}
        for y in range(top, bottom):
            relative_y = y - top
            band_index = min(len(counts) - 1,
                             relative_y * len(counts) // (bottom - top))
            band_color = tuple(counts)[band_index]
            band_areas[band_color] += right - left
            offset = (y * width + left) * 4
            end = (y * width + right) * 4
            while offset < end:
                color = encoded.get(bytes(pixels[offset:offset + 4]))
                if color is not None:
                    counts[color] += 1
                    if color == band_color:
                        band_counts[color] += 1
                offset += 4
        region_known[component] = {"bounds": [left, top, right, bottom],
                                   "area": (right - left) * (bottom - top),
                                   "known_colors": counts,
                                   "band_known_colors": band_counts,
                                   "band_areas": band_areas}
    return {"width": width, "height": height, "sha256": sha256_bytes(payload),
            "pixels_sha256": sha256_bytes(bytes(pixels)), "known_colors": known,
            "region_known_colors": region_known, "bytes": len(payload)}


def require_fixture_colors(frame: dict, component: str, record: dict):
    colors = FIXTURE_COLORS.get(component, ())
    region = frame.get("region_known_colors", {}).get(component)
    expected_bounds = [record[name] for name in ("left", "top", "right", "bottom")]
    if len(colors) == 3:
        coverage = all(region.get("band_known_colors", {}).get(color, 0) >=
                       max(100, region.get("band_areas", {}).get(color, 0) // 2)
                       for color in colors) if isinstance(region, dict) else False
    else:
        coverage = all(region.get("known_colors", {}).get(color, 0) >=
                       max(100, region.get("area", 0) // 5)
                       for color in colors) if isinstance(region, dict) else False
    require(colors and isinstance(region, dict) and region.get("bounds") == expected_bounds and
            type(region.get("area")) is int and region["area"] > 0 and coverage,
            "Framebuffer lacks the exact fixture palette/bands: " + component)


def require_fixture_colors_absent(frame: dict, component: str):
    colors = FIXTURE_COLORS.get(component, ())
    require(colors and all(frame["known_colors"].get(color, 0) == 0 for color in colors),
            "Rejected phone task pixels appeared on an external monitor")


def runtime_display_incarnations(status: dict, displays: dict) -> dict[int, dict]:
    snapshot = status.get("snapshot")
    require(isinstance(snapshot, dict), "Runtime stage lacks a bounded broker snapshot")
    result = {}
    for row in snapshot["display_incarnations"]:
        display = row["display_id"]
        require(display in displays and display not in result and
                row["density_dpi"] == displays[display]["density"] and
                row["bounds"] == [0, 0, displays[display]["width"], displays[display]["height"]],
                "Broker display incarnation differs from DisplayManager geometry")
        result[display] = row
    require(set(result) == set(displays),
            "Broker snapshot topology differs from sealed logical displays")
    return result


def runtime_task(stage: dict, component: str, *, required=True) -> dict | None:
    record = stage["records"].get(component)
    require(record is not None, "Runtime task binding lacks exact Android fixture record")
    if record["display"] == 0:
        matches = []
    else:
        require(component in TASK_TITLES, "Runtime task lacks an exact source-defined fixture title")
        broker_display = stage["broker_displays"].get(record["display"])
        require(broker_display is not None, "Runtime task names a foreign broker display")
        matches = [row for row in stage["status"]["snapshot"]["tasks"]
                   if row["package_name"] == FIXTURE and row["title"] == TASK_TITLES[component] and
                   row["visible"] is True and row["input_enabled"] is True and
                   row["display_token"] == broker_display["token"] and
                   row["bounds"] == [record[name] for name in
                                      ("left", "top", "right", "bottom")]]
    require(len(matches) <= 1 and (not required or len(matches) == 1),
            "Missing/ambiguous exact task in bounded broker snapshot")
    return matches[0] if matches else None


def exact_task(before: dict, after: dict, component: str, destination: int | None = None):
    require(component in before["records"] and component in after["records"],
            "Exact fixture task disappeared")
    for field in ("task", "instance"):
        require(before["records"][component][field] == after["records"][component][field],
                "Fixture task/instance was replaced")
    for field in ("task", "instance", "binder", "pid", "uid", "task_object", "activity_record"):
        require(before["identities"][component][field] == after["identities"][component][field],
                "Native Task/ActivityRecord/UID identity was replaced")
    expected = before["records"][component]["display"] if destination is None else destination
    require(after["records"][component]["display"] == expected and
            after["membership"].get(after["records"][component]["task"]) == expected,
            "Exact task reached the wrong Android display")
    return after["records"][component]


def task_input(stage: dict, component: str, uid: int, display: int, window_token: str):
    full = component.replace("/.", "/" + FIXTURE + ".")
    rows = [line for line in stage["raw"]["input"].splitlines() if full in line and
            re.search(r"\bname=" + re.escape(window_token) + r" " + re.escape(full) + r",", line) and
            re.search(r"\bdisplayId=" + str(display) + r",", line) and
            re.search(r"\bownerUid=" + str(uid) + r",", line)]
    require(len(rows) == 1 and not re.search(
        r"\b(?:NOT_VISIBLE|NOT_TOUCHABLE|DROP_INPUT|DROP_INPUT_IF_OBSCURED|PAUSE_DISPATCHING|SPY)\b",
        rows[0]), "Transferred task lacks a live exact app input handle")


def task_window_handle(stage: dict, component: str, task: int, display: int,
                       uid: int, identity: dict) -> str:
    """Bind a Task/ActivityRecord to its WindowManager token, even under Recents."""
    full = component.replace("/.", "/" + FIXTURE + ".")
    blocks = [block for block in re.split(r"(?=^\s*Window #\d+ Window\{)",
              stage["raw"]["windows"], flags=re.M) if full in block and
              re.search(r"\bmDisplayId=" + str(display) + r"\b", block) and
              re.search(r"\btaskId=" + str(task) + r"\b", block) and
              re.search(r"\bmOwnerUid=" + str(uid) + r"\b", block) and
              re.search(r"mActivityRecord=ActivityRecord\{" +
                        re.escape(identity["activity_record"]) + r"\b", block)]
    require(len(blocks) == 1,
            "Exact task lacks one WindowManager object under Recents")
    match = re.match(r"^\s*Window #\d+ Window\{([0-9a-f]+) u0 " +
                     re.escape(full) + r"\}:?", blocks[0])
    require(match is not None, "Exact Recents task window lacks its native token")
    input_rows = [line for line in stage["raw"]["input"].splitlines() if full in line and
                  re.search(r"\bname=" + re.escape(match[1]) + r" " + re.escape(full) + r",", line) and
                  re.search(r"\bdisplayId=" + str(display) + r",", line) and
                  re.search(r"\bownerUid=" + str(uid) + r",", line)]
    require(len(input_rows) == 1,
            "Exact Recents task window lacks its InputDispatcher object")
    return match[1]


def task_window(stage: dict, component: str, task: int, display: int, uid: int,
                identity: dict) -> str:
    full = component.replace("/.", "/" + FIXTURE + ".")
    blocks = [block for block in re.split(r"(?=^\s*Window #\d+ Window\{)",
              stage["raw"]["windows"], flags=re.M) if full in block and
              re.search(r"\bmDisplayId=" + str(display) + r"\b", block) and
              re.search(r"\btaskId=" + str(task) + r"\b", block) and
              re.search(r"\bmOwnerUid=" + str(uid) + r"\b", block) and
              re.search(r"mActivityRecord=ActivityRecord\{" +
                        re.escape(identity["activity_record"]) + r"\b", block) and
              "mHasSurface=true" in block and "HAS_DRAWN" in block and
              "isOnScreen=true" in block and "isVisible=true" in block]
    require(len(blocks) == 1, "Exact task lacks one drawn window on its destination")
    match = re.match(r"^\s*Window #\d+ Window\{([0-9a-f]+) u0 " +
                     re.escape(full) + r"\}:?", blocks[0])
    require(match is not None, "Exact task window lacks its native input token")
    return match[1]


def screenshot_window(stage: dict, systemui_uid: int):
    """Require a real, drawn SystemUI screenshot surface on the phone.

    A Launcher accessibility label is useful for locating the stock action,
    but it is not evidence that SystemUI handled it.  Bind the post-action
    claim to WindowManager's native window record and SystemUI's UID.
    """
    blocks = [block for block in re.split(r"(?=^\s*Window #\d+ Window\{)",
              stage["raw"]["windows"], flags=re.M) if
              re.search(r"(?i)\bscreenshot(?:animation|controller|preview|overlay|ui|window)?\b", block) and
              re.search(r"\bmDisplayId=0\b", block) and
              re.search(r"\bmOwnerUid=" + str(systemui_uid) + r"\b", block) and
              "mHasSurface=true" in block and "HAS_DRAWN" in block and
              "isOnScreen=true" in block and "isVisible=true" in block]
    require(len(blocks) == 1,
            "Screenshot activation lacks one drawn SystemUI phone window")


def no_protected_failure(raw: str):
    for match in re.finditer(r"\b(am_(?:anr|crash))\s*:\s*\[\s*[^,\]\n]+\s*,\s*[^,\]\n]+\s*,\s*([^,\]\n]+)", raw):
        process = match[2].strip().split(":", 1)[0]
        require(process not in {"system_server", SYSTEMUI, LAUNCHER},
                "Protected process crash/ANR in Recents lane: " + process)


def stage_from_files(directory: Path, row: dict, evidence: dict, uids: dict) -> dict:
    required = {"name", "ordinal", "trace_start", "trace_end", "files", "frames", "selection"}
    require(isinstance(row, dict) and set(row) == required and row["name"] in STAGES and
            type(row["ordinal"]) is int and row["ordinal"] == STAGES.index(row["name"]) and
            type(row["trace_start"]) is int and type(row["trace_end"]) is int and
            0 <= row["trace_start"] < row["trace_end"], "Malformed capture stage")
    require(isinstance(row["files"], dict) and set(row["files"]) == set(CAPTURE_KINDS),
            "Stage lacks a complete raw diagnostic set")
    raw = {}
    for kind, relative in row["files"].items():
        require(relative in evidence, "Unsealed stage diagnostic")
        raw[kind] = stable_bytes(literal_child(directory, relative)).decode("utf-8")
    require(re.search(r"(?m)^SERVICE\s+" + re.escape(SYSTEMUI) +
                      r"/\.SystemUIService\b[^\n]*\bpid=[1-9][0-9]*\b", raw["systemui"]) is not None and
            "Exception occurred while dumping:" not in raw["systemui"] and
            "No services match" not in raw["systemui"],
            "SystemUI service diagnostic is absent/failed/unbound")
    require(row["selection"] is None or isinstance(row["selection"], str),
            "Malformed Recents selection reference")
    if row["selection"] is not None:
        require(row["selection"] in evidence, "Unsealed Recents selection hierarchy")
        raw["selection"] = stable_bytes(literal_child(directory, row["selection"])).decode("utf-8")
    else:
        raw["selection"] = None
    records, membership = fixture_records(raw["fixture"])
    identities = fixture_identities(raw["fixture"], raw["activities"], records, uids[FIXTURE])
    displays = logical_displays(raw["display"])
    status = runtime_status(raw["conformance"])
    snapshot = status.get("snapshot")
    generation = snapshot.get("generation") if isinstance(snapshot, dict) else None
    require(type(generation) is int and generation > 0,
            "Stage lacks a live/retained runtime generation")
    broker_displays = runtime_display_incarnations(status, displays)
    shells = shell_incarnations(raw["activities"], raw["windows"], raw["input"], generation,
                                uids[APP], displays)
    homes = home_incarnations(raw["activities"], raw["windows"], raw["input"], uids[APP], displays)
    frames = {}
    require(isinstance(row["frames"], dict) and "0" in row["frames"],
            "Stage lacks the phone framebuffer")
    slots = {item["slot"] for item in displays.values()}
    require(set(row["frames"]) == {"0"} | {str(slot) for slot in slots},
            "Stage framebuffer set differs from actual connectors")
    for slot, relative in row["frames"].items():
        require(relative in evidence, "Unsealed framebuffer")
        display_id = 0
        if slot != "0":
            candidates = [item["display"] for item in displays.values()
                          if item["slot"] == int(slot)]
            require(len(candidates) == 1, "Framebuffer slot lacks one logical display")
            display_id = candidates[0]
        regions = {component: [record[name] for name in
                               ("left", "top", "right", "bottom")]
                   for component in PIXEL_EXPECTATIONS.get(row["name"], ())
                   for record in [records.get(component)]
                   if record is not None and record["display"] == display_id}
        info = png_info(stable_bytes(literal_child(directory, relative)), regions)
        expected = (1080, 2400) if slot == "0" else DISPLAY_SPECS[int(slot)][:2]
        require((info["width"], info["height"]) == expected,
                "Framebuffer geometry differs from connector")
        frames[int(slot)] = info
    no_protected_failure(raw["log"])
    return {"name": row["name"], "raw": raw, "records": records, "membership": membership,
            "identities": identities, "displays": displays, "status": status,
            "broker_displays": broker_displays, "shells": shells, "homes": homes, "frames": frames,
            "focused_display": focused_display(raw["windows"]),
            "trace_start": row["trace_start"], "trace_end": row["trace_end"]}


def validate_stage_manifest(rows: list) -> set[str]:
    """Validate producer-owned names, paths and a non-overlapping chronology.

    Semantic parsing alone must not let two claims alias one convenient raw
    dump or let a later input action be pulled backwards into an earlier
    stage's range.  The producer has a deterministic layout, so the auditor
    can reject every other layout before opening any stage evidence.
    """
    require(isinstance(rows, list) and len(rows) == len(STAGES),
            "Recents stages are missing/reordered")
    expected_extensions = {kind: ("xml" if kind == "hierarchy" else "txt")
                           for kind in CAPTURE_KINDS}
    referenced = set()
    previous_end = None
    for ordinal, (name, row) in enumerate(zip(STAGES, rows)):
        required = {"name", "ordinal", "trace_start", "trace_end", "files", "frames", "selection"}
        require(isinstance(row, dict) and set(row) == required and
                row["name"] == name and row["ordinal"] == ordinal and
                type(row["trace_start"]) is int and type(row["trace_end"]) is int and
                0 <= row["trace_start"] < row["trace_end"] and
                (previous_end is None or previous_end <= row["trace_start"]),
                "Recents stage manifest has an aliased/reordered trace range")
        previous_end = row["trace_end"]
        prefix = "stages/%02d-%s/" % (ordinal, name)
        expected_files = {kind: prefix + kind + "." + extension
                          for kind, extension in expected_extensions.items()}
        require(row["files"] == expected_files and isinstance(row["frames"], dict) and
                row["frames"] and all(isinstance(slot, str) and slot.isdigit() and
                    relative == prefix + "frame-" + slot + ".png"
                    for slot, relative in row["frames"].items()),
                "Recents stage manifest uses an unexpected/aliased evidence path")
        expected_selection = ("selections/%02d-%s.xml" % (ordinal, name)
                              if name in SELECTION_STAGES else None)
        require(row["selection"] == expected_selection,
                "Recents stage selection path/presence changed")
        paths = [*row["files"].values(), *row["frames"].values()]
        if row["selection"] is not None:
            paths.append(row["selection"])
        require(not referenced.intersection(paths) and len(set(paths)) == len(paths),
                "Recents stages alias sealed evidence")
        referenced.update(paths)
    return referenced


def command_argv(row):
    return row.get("argv", []) if isinstance(row, dict) else []


def reviewed_command(argv):
    require(isinstance(argv, list) and argv and all(isinstance(item, str) for item in argv),
            "Malformed command argv")
    lowered = [item.lower() for item in argv]
    require(not any(item in lowered for item in ("force-stop", "move-task", "set-focused-task")) and
            not ("settings" in lowered and any(item in lowered for item in ("put", "delete", "reset"))) and
            not ("pm" in lowered and any(item in lowered for item in ("clear", "uninstall", "grant"))) and
            not ("am" in lowered and "task" in lowered) and
            not ("cmd" in lowered and "activity" in lowered and "task" in lowered) and
            not ("service" in lowered and "call" in lowered) and "wm" not in lowered,
            "Producer used privileged/synthetic task or settings mutation")
    require(argv[:1] == ["docker"], "Producer escaped the exact container boundary")
    require(not any(re.search(r"[;&|`$<>\r\n]", item) for item in argv),
            "Producer command contains shell syntax")
    if argv[:2] == ["docker", "exec"]:
        require(len(argv) >= 4 and argv[3] in {"adb", "cat", "sha256sum", "mkdir", "find", "rm"},
                "Producer used an unreviewed container executable/wrapper")
        if argv[3] == "adb":
            require(len(argv) >= 8 and argv[4:6] == ["-s", SERIAL] and
                    argv[6] in {"shell", "exec-out", "emu"},
                    "Producer used an unreviewed adb command family")
            tail = argv[7:]
            require(tail, "Producer supplied an empty adb command")
            if argv[6] == "shell":
                allowed = {"cat", "sha256sum", "getprop", "getenforce", "am", "pm", "settings",
                           "cmd", "dumpsys", "pidof", "su", "input", "logcat",
                           "uiautomator", "rm"}
                require(tail[0] in allowed,
                        "Producer used an unreviewed Android shell executable")
                if tail[0] == "am":
                    require(len(tail) >= 2 and tail[1] in
                            {"get-current-user", "start", "instrument"},
                            "Producer used an unreviewed ActivityManager launch alias")
                if tail[0] == "cmd":
                    forward = (len(tail) == 8 and tail[1:7] ==
                               ["package", "list", "packages", "-U", "--user", "0"] and
                               tail[7] in {APP, FIXTURE, LAUNCHER, SYSTEMUI})
                    reverse = (len(tail) == 9 and tail[1:8] ==
                               ["package", "list", "packages", "-U", "--user", "0", "--uid"] and
                               re.fullmatch(r"[0-9]+", tail[8]) is not None)
                    resolve_home = tuple(tail) == PHONE_HOME_RESOLVE
                    require(forward or reverse or resolve_home,
                            "Producer used an unreviewed cmd service")
                if tail[0] == "pm":
                    require(len(tail) == 3 and tail[1] == "path" and
                            tail[2] in {APP, FIXTURE, *PRIVILEGED_SYSTEM_PACKAGES},
                            "Producer used an unreviewed package mutation")
                if tail[0] == "settings":
                    require(tail == ["settings", "--user", "0", "get", "secure",
                                     "wonad_external_desktop_enabled"],
                            "Producer used an unreviewed settings operation")
                if tail[0] == "sha256sum":
                    require(len(tail) == 2 and
                            (tail[1] in OS_GUEST_PATHS.values() or
                             tail[1] in PRIVILEGED_SYSTEM_PACKAGES.values() or
                             re.fullmatch(r"/data/app/[A-Za-z0-9_+/.=~-]+/base\.apk", tail[1]) is not None),
                            "Producer used an unreviewed guest hash target")
                if tail[0] == "logcat":
                    require(tuple(tail) in {
                        LOG_CLEAR,
                        PHONE_OVERVIEW_LOG,
                        ("logcat", "-b", "main", "-b", "events", "-d", "-v",
                         "threadtime", "-t", "4000")},
                        "Producer used an unreviewed log clear/read")
                if tail[0] == "uiautomator":
                    require(len(tail) == 3 and tail[1] == "dump" and
                            re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-(?:capture-)?"
                                         r"[0-9a-f]{16,32}(?:-\d+)?\.xml", tail[2]) is not None,
                            "Producer used an unreviewed UIAutomator operation")
                if tail[0] == "rm":
                    require(len(tail) == 3 and tail[1] == "--" and
                            re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-(?:capture-)?"
                                         r"[0-9a-f]{16,32}(?:-\d+)?\.xml", tail[2]) is not None,
                            "Producer used an unreviewed Android cleanup")
                if tail[0] == "input":
                    keyboard = (len(tail) == 6 and tail[1:5] ==
                        ["keyboard", "-d", "0", "keyevent"] and tail[5] in {
                            "KEYCODE_HOME", "KEYCODE_ALL_APPS", "KEYCODE_APP_SWITCH",
                            "KEYCODE_BACK"})
                    pointer = (len(tail) in {7, 10} and tail[1] in
                        {"touchscreen", "mouse"} and tail[2:4] == ["-d", tail[3]] and
                        re.fullmatch(r"(?:0|[1-9][0-9]*)", tail[3]) is not None)
                    if pointer and tail[4] == "tap":
                        pointer = len(tail) == 7 and all(
                            re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None
                            for value in tail[5:])
                    elif pointer and tail[4] == "swipe":
                        pointer = (tail[1] == "touchscreen" and tail[3] == "0" and
                            len(tail) == 10 and all(
                                re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is not None
                                for value in tail[5:]))
                    else:
                        pointer = False
                    require(keyboard or pointer,
                            "Producer used an unreviewed Android input grammar")
                if tail[0] == "dumpsys":
                    allowed_dumps = (
                        tail == ["dumpsys", "activity", "activities"],
                        tail == ["dumpsys", "activity", FIXTURE],
                        tail == ["dumpsys", "window", "windows"],
                        tail == ["dumpsys", "window", "displays"],
                        tail == ["dumpsys", "input"],
                        tail == ["dumpsys", "display"],
                        tail == ["dumpsys", "activity", "service", SYSTEMUI + "/.SystemUIService"],
                        tuple(tail) == PHONE_TIS_DUMP,
                        tail[:4] == ["dumpsys", "activity", "service", APP + "/.ConformanceService"] and
                            (len(tail) == 4 or len(tail) == 8 and tail[4] == "runtime-command"),
                    )
                    require(any(allowed_dumps), "Producer used an unreviewed dumpsys operation")
            elif argv[6] == "exec-out":
                require((tail == ["screencap", "-p"] or
                         len(tail) == 2 and tail[0] == "cat" and
                         re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-(?:capture-)?"
                                      r"[0-9a-f]{16,32}(?:-\d+)?\.xml", tail[1]) is not None),
                        "Producer used an unreviewed adb exec-out command")
            else:
                require((len(tail) >= 2 and tail[:2] in
                         (["multidisplay", "add"], ["multidisplay", "del"])) or
                        (len(tail) == 5 and tail[:3] ==
                         ["screenrecord", "screenshot", "--display"]),
                        "Producer used an unreviewed emulator-console command")
        elif argv[3] in {"cat", "sha256sum"}:
            paths = ["/opt/wonad/manifest.json", *BUNDLED_APKS.values()]
            require((argv[3] == "cat" and argv[4:] == ["/opt/wonad/manifest.json"]) or
                    (argv[3] == "sha256sum" and argv[4:] == paths),
                    "Producer read an unreviewed candidate artifact")
        else:
            remote = r"/state/phase1-recents-[0-9a-f]{32}-[0-9a-f]{8}-[123]"
            require(
                (argv[3] == "mkdir" and len(argv) == 8 and
                 argv[4:7] == ["-m", "700", "--"] and
                 re.fullmatch(remote, argv[7]) is not None) or
                (argv[3] == "find" and len(argv) == 13 and
                 re.fullmatch(remote, argv[4]) is not None and
                 argv[5:] == ["-maxdepth", "1", "-type", "f", "-name", "*.png",
                              "-printf", "%f\\n"]) or
                (argv[3] == "rm" and len(argv) == 7 and argv[4:6] == ["-rf", "--"] and
                 re.fullmatch(remote, argv[6]) is not None),
                "Producer used an unreviewed framebuffer-directory operation")
    elif argv[:2] == ["docker", "container"]:
        require(len(argv) == 4 and argv[2] in {"inspect", "diff"},
                "Producer used an unreviewed container lifecycle command")
    else:
        require(len(argv) == 4 and argv[1] == "cp" and
                re.fullmatch(r"[0-9a-f]{64}:/state/phase1-recents-[0-9a-f]{32}-"
                             r"[0-9a-f]{8}-[123]/"
                             r"[A-Za-z0-9_.-]+\.png", argv[2]) is not None and
                ":" not in argv[3],
                "Producer used an unreviewed docker command/copy direction")
    if "su" in lowered:
        index = lowered.index("su")
        require(len(argv) == index + 4 and argv[index:index + 3] == ["su", "0", "cat"] and
                re.fullmatch(r"/proc/[1-9][0-9]*/stat", argv[-1]) is not None,
                "Producer used unreviewed root authority")
    return True


def trace_rows(trace: list, argv: list[str]) -> list[dict]:
    return [row for row in trace if row.get("kind") == "command" and
            row.get("argv") == argv and row.get("returncode") == 0]


def validate_identity_trace(trace: list, report: dict, stages: dict):
    container = report["container_id"]
    adb = ["docker", "exec", container, "adb", "-s", SERIAL]

    def one(argv, label):
        rows = trace_rows(trace, argv)
        require(len(rows) == 1 and isinstance(rows[0].get("output"), str),
                "Missing/ambiguous original " + label + " observation")
        return rows[0]

    inspected = one(["docker", "container", "inspect", container], "container identity")
    try:
        values = json.loads(inspected["output"], object_pairs_hook=strict_object)
    except json.JSONDecodeError as error:
        raise EvidenceError("Malformed original container inspection") from error
    require(len(values) == 1 and values[0].get("Id") == container and
            values[0].get("Image") == report["image_id"] and
            values[0].get("State", {}).get("Running") is True and
            values[0].get("HostConfig", {}).get("NetworkMode") == "none" and
            values[0].get("HostConfig", {}).get("Privileged") is False and
            "ALL" in values[0].get("HostConfig", {}).get("CapDrop", []) and
            any(str(item).startswith("no-new-privileges")
                for item in values[0].get("HostConfig", {}).get("SecurityOpt", [])) and
            not any(mount.get("Destination") == "/opt/wonad" or
                    str(mount.get("Destination", "")).startswith("/opt/wonad/")
                    for mount in values[0].get("Mounts", [])),
            "Report identity differs from original isolated container inspection")

    manifest_argv = ["docker", "exec", container, "cat", "/opt/wonad/manifest.json"]
    manifest_row = one(manifest_argv, "candidate manifest")
    manifest = candidate_manifest(manifest_row["output"], report["fingerprint"])
    bundle_paths = ["/opt/wonad/manifest.json", *BUNDLED_APKS.values()]
    hashes = sha256sum_output(one(
        ["docker", "exec", container, "sha256sum", *bundle_paths],
        "candidate root-filesystem hashes")["output"], bundle_paths)
    require(hashes["/opt/wonad/manifest.json"] ==
                sha256_bytes(manifest_row["output"].encode()) and
            all(hashes[path] == manifest["artifacts"][
                "conformance" if package == APP else "fixture"]["sha256"]
                for package, path in BUNDLED_APKS.items()),
            "Candidate manifest/APK root-filesystem bytes changed")
    diff = one(["docker", "container", "diff", container], "container filesystem delta")
    require(not any(re.fullmatch(r"[ACD] /opt/wonad(?:/.*)?", line)
                    for line in diff["output"].splitlines()),
            "Candidate /opt/wonad root filesystem changed after image creation")

    observations = (
        (["shell", "cat", "/proc/sys/kernel/random/boot_id"], report["boot_id"], "boot ID"),
        (["shell", "getprop", "ro.build.fingerprint"], report["fingerprint"], "fingerprint"),
        (["shell", "getprop", "sys.boot_completed"], "1", "completed boot"),
        (["shell", "getenforce"], "Enforcing", "SELinux state"),
        (["shell", "am", "get-current-user"], "0", "active user"),
        (["shell", "settings", "--user", "0", "get", "secure",
          "wonad_external_desktop_enabled"], "1", "Wonad consent"),
    )
    for suffix, expected, label in observations:
        require(one(adb + suffix, label)["output"].strip() == expected,
                "Original " + label + " differs from report/lane precondition")
    for package, role in ((APP, "conformance"), (FIXTURE, "fixture")):
        output = one(adb + ["shell", "pm", "path", package], package + " installation")["output"]
        require(len(output.splitlines()) == 1 and
                re.fullmatch(r"package:/[A-Za-z0-9_+/.=~-]+", output.strip()) is not None,
                "Required conformance artifact path is missing/ambiguous")
        path = output.strip().removeprefix("package:")
        installed = sha256sum_output(one(adb + ["shell", "sha256sum", path],
            package + " installed bytes")["output"], [path])
        require(installed[path] == manifest["artifacts"][role]["sha256"],
                "Installed package differs from candidate package/version/signer bytes")
    privileged = {}
    system_image = manifest["product_images"][SYSTEM_IMAGE]
    for package, path in PRIVILEGED_SYSTEM_PACKAGES.items():
        output = one(adb + ["shell", "pm", "path", package],
                     package + " active privileged path")["output"]
        require(active_system_package_path(output, package) == path,
                "Active privileged package path changed")
        observed = sha256sum_output(one(adb + ["shell", "sha256sum", path],
            package + " active privileged bytes")["output"], [path])
        if package == SYSTEMUI:
            require(observed[path] == manifest["os_artifacts"][SYSTEMUI],
                    "Running SystemUI bytes differ from the candidate OS artifact")
        privileged[package] = {"path": path, "sha256": observed[path],
            "system_image_sha256": system_image, "active_system_package": True}
    require(report["privileged_packages"] == privileged,
            "Privileged Launcher/SystemUI identity differs from the active immutable system packages")
    for role, path in OS_GUEST_PATHS.items():
        if role == SYSTEMUI:
            continue
        observed = sha256sum_output(one(adb + ["shell", "sha256sum", path],
            role + " running OS bytes")["output"], [path])
        require(observed[path] == manifest["os_artifacts"][role],
                "Running guest OS artifact differs from exact candidate image")

    attaches = [row for row in trace if len(command_argv(row)) >= 10 and
                command_argv(row)[:6] == adb and
                command_argv(row)[6:9] == ["emu", "multidisplay", "add"]]
    require(len(attaches) >= 3, "Original trace lacks the initial mixed-display attachment")
    first_attach = min(row["sequence"] for row in attaches)
    service_argv = adb + ["shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"]
    initial_services = [row for row in trace_rows(trace, service_argv)
                        if row["sequence"] < first_attach]
    require(len(initial_services) == 1 and
            inactive_conformance_status(initial_services[0]["output"]).get("state") in
                ("absent", "idle", "passed", "failed", "stopped"),
            "Dedicated lane did not prove an inactive initial conformance service")
    display_argv = adb + ["shell", "dumpsys", "display"]
    initial_displays = [row for row in trace_rows(trace, display_argv)
                        if row["sequence"] < first_attach]
    require(len(initial_displays) == 1 and not logical_displays(initial_displays[0]["output"]),
            "Dedicated lane did not prove an initially empty external topology")


def protected_process_epochs(trace: list, report: dict, stages: dict) -> dict:
    prefix = ["docker", "exec", report["container_id"], "adb", "-s", SERIAL, "shell"]
    names = ("system_server", SYSTEMUI, LAUNCHER)
    result = {"before": {}, "after": {}}
    positions = {"before": {}, "after": {}}
    boundary_before = stages["baseline"]["trace_start"]
    boundary_after = stages["unavailable"]["trace_end"]
    consumed_stats = set()
    all_stats = {index for index, row in enumerate(trace)
                 if command_argv(row)[:len(prefix) + 3] == prefix + ["su", "0", "cat"] and
                 len(command_argv(row)) == len(prefix) + 4 and
                 command_argv(row)[-1].startswith("/proc/") and
                 command_argv(row)[-1].endswith("/stat")}
    for name in names:
        rows = [(index, row) for index, row in enumerate(trace)
                if command_argv(row) == prefix + ["pidof", name]]
        require(len(rows) == 2, "Missing paired protected process observations: " + name)
        for index, row in rows:
            require(row.get("returncode") == 0 and isinstance(row.get("output"), str) and
                    re.fullmatch(r"[1-9][0-9]*\s*", row["output"]) is not None and
                    index + 1 < len(trace), "Malformed protected process PID: " + name)
            pid = int(row["output"])
            stat_row = trace[index + 1]
            require(command_argv(stat_row) == prefix + ["su", "0", "cat", f"/proc/{pid}/stat"] and
                    stat_row.get("returncode") == 0 and isinstance(stat_row.get("output"), str),
                    "Protected PID lacks its immediately paired /proc epoch: " + name)
            match = re.fullmatch(r"([1-9][0-9]*) \(.*\) [A-Z] (.+)\n?", stat_row["output"])
            fields = match[2].split() if match is not None else []
            require(match is not None and int(match[1]) == pid and len(fields) > 18 and
                    re.fullmatch(r"[1-9][0-9]*", fields[18]) is not None,
                    "Malformed protected process /proc epoch: " + name)
            side = "before" if index < boundary_before else "after" if index >= boundary_after else ""
            require(side and name not in result[side],
                    "Protected process epoch occurs inside the Recents scenario: " + name)
            result[side][name] = {"pid": pid, "start_ticks": int(fields[18])}
            positions[side][name] = index
            consumed_stats.add(index + 1)
    require(all(set(result[side]) == set(names) for side in result) and
            consumed_stats == all_stats and result["before"] == result["after"],
            "Protected system_server/SystemUI/Launcher epochs changed across Recents")
    return result


def validate_frame_trace(trace: list, low: int, high: int, directory: Path,
                         container: str, slot: int, relative: str):
    rows = [(index, row) for index, row in enumerate(trace[low:high], start=low)
            if row.get("evidence") == relative]
    require(len(rows) == 1, "Framebuffer lacks one original capture command")
    index, row = rows[0]
    if slot == 0:
        require(command_argv(row) == ["docker", "exec", container, "adb", "-s", SERIAL,
                "exec-out", "screencap", "-p"] and row.get("returncode") == 0,
                "Phone framebuffer did not originate in exact screencap")
        return
    argv = command_argv(row)
    require(len(argv) == 4 and argv[:2] == ["docker", "cp"] and
            argv[3] == str(literal_child(directory, relative)) and row.get("returncode") == 0 and
            argv[2].startswith(container + ":/state/phase1-recents-") and
            re.fullmatch(re.escape(container) + r":(/state/phase1-recents-[^/]+-" + str(slot) +
                         r")/[A-Za-z0-9_.-]+\.png", argv[2]) is not None,
            "External framebuffer copy is not bound to its exact container/slot")
    remote = argv[2].split(":", 1)[1].rsplit("/", 1)[0]
    basename = argv[2].rsplit("/", 1)[1]
    require(index >= low + 3 and index + 1 < high,
            "External framebuffer lifecycle escapes its stage")
    mkdir, screenshot, find, cleanup = (
        trace[index - 3], trace[index - 2], trace[index - 1], trace[index + 1])
    require(command_argv(mkdir) ==
                ["docker", "exec", container, "mkdir", "-m", "700", "--", remote] and
            mkdir.get("returncode") == 0 and
            command_argv(screenshot) ==
                ["docker", "exec", container, "adb", "-s", SERIAL, "emu", "screenrecord",
                 "screenshot", "--display", str(slot), remote] and
            screenshot.get("returncode") == 0 and isinstance(screenshot.get("output"), str) and
            "OK" in screenshot["output"] and "KO:" not in screenshot["output"] and
            command_argv(find) ==
                ["docker", "exec", container, "find", remote, "-maxdepth", "1", "-type", "f",
                 "-name", "*.png", "-printf", "%f\\n"] and
            find.get("returncode") == 0 and find.get("output", "").splitlines() == [basename] and
            command_argv(cleanup) ==
                ["docker", "exec", container, "rm", "-rf", "--", remote] and
            cleanup.get("returncode") == 0,
            "External framebuffer lacks an exact atomic mkdir/capture/find/copy/cleanup lifecycle")


def validate_external_copy_inventory(trace: list, report: dict):
    """Consume every docker copy as one declared outward framebuffer read.

    In particular, this forbids a host-to-container copy between the emulator
    screenshot and the evidence-bearing copy.  Merely finding the expected
    copy is not enough: an intervening overwrite would otherwise let crafted
    host pixels masquerade as the emulator framebuffer.
    """
    expected = {
        relative
        for stage in report["stages"]
        for slot, relative in stage["frames"].items()
        if slot != "0"
    }
    rows = [row for row in trace if command_argv(row)[:2] == ["docker", "cp"]]
    require(len(rows) == len(expected) and
            {row.get("evidence") for row in rows} == expected and
            all(row.get("returncode") == 0 for row in rows),
            "Docker copy inventory contains a forged/intervening framebuffer copy")
    return True


def validate_frame_capture_inventory(trace: list, report: dict, container: str):
    external = sum(slot != "0" for stage in report["stages"]
                   for slot in stage["frames"])
    families = {
        "mkdir": [row for row in trace if command_argv(row)[:4] ==
                  ["docker", "exec", container, "mkdir"]],
        "find": [row for row in trace if command_argv(row)[:4] ==
                 ["docker", "exec", container, "find"]],
        "cleanup": [row for row in trace if command_argv(row)[:4] ==
                    ["docker", "exec", container, "rm"]],
        "screenshot": [row for row in trace if command_argv(row)[:9] ==
                       ["docker", "exec", container, "adb", "-s", SERIAL, "emu",
                        "screenrecord", "screenshot"]],
    }
    require(all(len(rows) == external for rows in families.values()),
            "Framebuffer capture inventory contains an extra/missing mutator")
    return True


def validate_log_inventory(trace: list, report: dict, stages: dict):
    """Consume main-buffer clears and cumulative event reads at declared boundaries."""
    shell = ["docker", "exec", report["container_id"], "adb", "-s", SERIAL, "shell"]
    log_rows = [(index, row) for index, row in enumerate(trace)
                if command_argv(row)[:len(shell) + 1] == shell + ["logcat"]]
    action_stages = (
        "task_remove_card", "transfer_1_menu", "transfer_2_menu", "transfer_3_menu",
        "selected_display_rejected", "same_slot_rejected", "screenshot_menu", "split_menu",
    )
    clears = [(index, row) for index, row in log_rows
              if command_argv(row) == shell + list(LOG_CLEAR)]
    consumed = set()
    for name in action_stages:
        stage = stages[name]
        rows = [index for index, row in clears
                if stage["trace_start"] <= index < stage["trace_end"] and
                row.get("returncode") == 0]
        require(len(rows) == 1, "Action lacks one exact pre-action main-buffer clear: " + name)
        consumed.add(rows[0])
    require(len(clears) == len(consumed),
            "Extra main-buffer clear escaped the reviewed action boundaries")

    declared = {row["files"]["log"] for row in report["stages"]}
    reads = [(index, row) for index, row in log_rows
             if command_argv(row) == shell +
                ["logcat", "-b", "main", "-b", "events", "-d", "-v", "threadtime",
                 "-t", "4000"]]
    require(len(reads) == len(declared) and
            {row.get("evidence") for _, row in reads} == declared and
            all(row.get("returncode") == 0 for _, row in reads) and
            len(log_rows) == len(clears) + len(reads),
            "Event-log read inventory contains an undeclared/ambiguous operation")
    return True


def require_stage_log_after(trace: list, stage: dict, relative: str,
                            prior_indexes: list[int], label: str):
    rows = [index for index in range(stage["trace_start"], stage["trace_end"])
            if trace[index].get("evidence") == relative]
    require(len(rows) == 1 and prior_indexes and max(prior_indexes) < rows[0],
            "Sealed event log precedes the claimed action/checkpoint: " + label)
    return rows[0]


def validate_hierarchy_lifecycle(trace: list, row: dict, container: str, remote: str):
    """Prove an XML read came from one fresh UIAutomator dump and cleanup."""
    indexes = [index for index, candidate in enumerate(trace) if candidate is row]
    require(len(indexes) == 1, "Hierarchy trace row is aliased")
    index = indexes[0]
    shell = ["docker", "exec", container, "adb", "-s", SERIAL, "shell"]
    require(index > 0 and index + 1 < len(trace) and
            command_argv(trace[index - 1]) == shell + ["uiautomator", "dump", remote] and
            trace[index - 1].get("returncode") == 0 and
            command_argv(trace[index + 1]) == shell + ["rm", "--", remote] and
            trace[index + 1].get("returncode") in {0, 1},
            "Hierarchy XML lacks its exact UIAutomator dump/read/cleanup lifecycle")
    return index


def launch_evidence_paths() -> set[str]:
    return {"launches/%02d-%s-%d.xml" % (STAGES.index(stage), stage, index)
            for stage, components in LAUNCH_PLAN.items()
            for index, _ in enumerate(components)}


def validate_launcher_launches(trace: list, report: dict, stages: dict, directory: Path):
    """Bind each scenario Task to an ordinary, sealed Launcher All Apps tap."""
    prefix = ["docker", "exec", report["container_id"], "adb", "-s", SERIAL]
    shell = prefix + ["shell"]
    fixture_argv = shell + ["dumpsys", "activity", FIXTURE]
    for stage_name, components in LAUNCH_PLAN.items():
        stage = stages[stage_name]
        low, high = stage["trace_start"], stage["trace_end"]
        previous_tap = low - 1
        for launch_index, component in enumerate(components):
            relative = "launches/%02d-%s-%d.xml" % (
                STAGES.index(stage_name), stage_name, launch_index)
            rows = [(index, row) for index, row in enumerate(trace[low:high], start=low)
                    if row.get("evidence") == relative]
            require(len(rows) == 1 and rows[0][1].get("returncode") == 0,
                    "Ordinary task launch lacks one sealed All Apps hierarchy")
            hierarchy_index, hierarchy_row = rows[0]
            argv = command_argv(hierarchy_row)
            require(argv[:6] == prefix and argv[6:8] == ["exec-out", "cat"] and len(argv) == 9 and
                    re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml",
                                 argv[8]) is not None,
                    "Launcher evidence did not originate in its exact UIAutomator file")
            validate_hierarchy_lifecycle(trace, hierarchy_row, report["container_id"], argv[8])
            xml = stable_bytes(literal_child(directory, relative)).decode("utf-8")
            point = launcher_icon(xml, LABELS[component])
            taps = [(index, row) for index, row in enumerate(trace[low:high], start=low)
                    if command_argv(row) == shell + ["input", "touchscreen", "-d", "0", "tap",
                                                    *map(str, point)] and
                    row.get("returncode") == 0 and index > hierarchy_index]
            require(len(taps) == 1, "Launcher icon is not bound to one exact ordinary tap")
            tap_index = taps[0][0]
            homes = [index for index, row in enumerate(trace[low:hierarchy_index], start=low)
                     if command_argv(row) == shell +
                        ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"] and
                        row.get("returncode") == 0 and index > previous_tap]
            drawers = [index for index, row in enumerate(trace[low:hierarchy_index], start=low)
                       if command_argv(row) == shell +
                          ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_ALL_APPS"] and
                          row.get("returncode") == 0 and index > previous_tap]
            require(homes and drawers and min(homes) < min(drawers) < hierarchy_index < tap_index,
                    "Launcher launch did not traverse Home then genuine All Apps")
            prior = []
            after = []
            for index, row in enumerate(trace[low:high], start=low):
                if command_argv(row) != fixture_argv or row.get("returncode") != 0 or \
                        not isinstance(row.get("output"), str):
                    continue
                try:
                    records, _ = fixture_records(row["output"])
                except EvidenceError:
                    continue
                if index < tap_index and index > previous_tap and component not in records:
                    prior.append(index)
                if index > tap_index and component in records and records[component]["display"] == 0:
                    after.append(index)
            require(prior and after,
                    "Launcher tap lacks ordered absent-before/present-after Task evidence")
            previous_tap = tap_index


def require_consumed_input_inventory(trace: list, shell: list[str], consumed: set[int]):
    inputs = {index: row for index, row in enumerate(trace)
              if command_argv(row)[:len(shell) + 1] == shell + ["input"]}
    require(consumed == set(inputs) and
            all(inputs[index].get("returncode") == 0 for index in consumed),
            "Unconsumed or failed keyboard/mouse/touch input escaped the Recents scenario")
    return True


def validate_phone_overview_trace(trace: list, container: str, directory: Path,
                                  stage_name: str, low: int, high: int) -> dict:
    """Independently replay raw Home/tap/native-focus/one-toggle/Overview chronology."""
    require(stage_name in SELECTION_STAGES or stage_name == "task_remove_card",
            "Unreviewed phone Overview stage")
    prefix = "phone-overview/" + stage_name + "/"
    shell = ["docker", "exec", container, "adb", "-s", SERIAL, "shell"]
    def command(suffix):
        matches = [(index, row) for index, row in enumerate(trace[low:high], start=low)
                   if command_argv(row) == shell + list(map(str, suffix))]
        require(len(matches) == 1 and matches[0][1].get("returncode") == 0,
                "Missing/ambiguous successful phone Overview input")
        return matches[0][0]
    def read(relative, suffix=None, hierarchy=False):
        rows = [(index, row) for index, row in enumerate(trace[low:high], start=low)
                if row.get("evidence") == prefix + relative]
        require(len(rows) == 1 and rows[0][1].get("returncode") == 0,
                "Missing/ambiguous sealed phone Overview observation")
        index, row = rows[0]
        argv = command_argv(row)
        if hierarchy:
            require(argv[:8] == shell[:6] + ["exec-out", "cat"] and len(argv) == 9 and
                    re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml",
                                 argv[8]) is not None,
                    "Phone Overview hierarchy has no exact ordinary UI source")
            validate_hierarchy_lifecycle(trace, row, container, argv[8])
        else:
            require(argv == shell + list(suffix), "Phone focus observation used a different source")
        raw = stable_bytes(literal_child(directory, prefix + relative))
        require(len(raw) <= 512 * 1024 and row.get("output_sha256") == hashlib.sha256(raw).hexdigest(),
                "Phone Overview raw observation is oversized or changed")
        try:
            return index, raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvidenceError("Phone Overview raw observation is not UTF-8") from error
    def attempts(pattern):
        indices = []
        for row in trace[low:high]:
            match = re.fullmatch(re.escape(prefix) + pattern, str(row.get("evidence", "")))
            if match:
                indices.append(int(match[1]))
        require(indices == list(range(len(indices))) and 1 <= len(indices) <= PHONE_OVERVIEW_ATTEMPTS,
                "Phone Overview retry sequence is duplicated, reordered or unbounded")
        return indices
    overview_logs = [(index, row) for index, row in enumerate(trace[low:high], start=low)
                     if command_argv(row) == shell + list(PHONE_OVERVIEW_LOG)]
    require(len(overview_logs) == 2 and all(row.get("returncode") == 0 and
            isinstance(row.get("output"), str) and
            len(row["output"].encode("utf-8")) <= 512 * 1024 and
            "\x00" not in row["output"] for _, row in overview_logs),
            "Missing/ambiguous bounded Quickstep diagnostic log observations")
    resolve_index, resolved = read("resolve.txt", PHONE_HOME_RESOLVE)
    require(resolved in {PHONE_HOME_COMPONENT, PHONE_HOME_COMPONENT + "\n"},
            "Phone HOME resolver does not name the exact pinned Launcher")
    home = command(["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
    home_reads = [read("home-%02d.xml" % attempt, hierarchy=True)
                  for attempt in attempts(r"home-(\d{2})\.xml")]
    point = phone_home_workspace(home_reads[-1][1])
    before = [read("before-" + kind + ".txt", ["dumpsys", *tail])
              for kind, tail in (("activities", ("activity", "activities")),
                                 ("displays", ("window", "displays")),
                                 ("windows", ("window", "windows")))]
    tap = command(["input", "mouse", "-d", "0", "tap", *point])
    focus = [[read("focus-%02d-%s.txt" % (attempt, kind), ["dumpsys", *tail])
              for kind, tail in (("activities", ("activity", "activities")),
                                 ("displays", ("window", "displays")),
                                 ("windows", ("window", "windows")))]
             for attempt in attempts(r"focus-(\d{2})-activities\.txt")]
    phone_home_focus(*(value[1] for value in focus[-1]))
    before_tis = read("before-tis.txt", PHONE_TIS_DUMP)
    before_tis_state = phone_tis_state(before_tis[1])
    before_log = overview_logs[0]
    switch = command(["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_APP_SWITCH"])
    after_switch = [read("after-switch-" + kind + ".txt", ["dumpsys", *tail])
                    for kind, tail in (("activities", ("activity", "activities")),
                                       ("displays", ("window", "displays")),
                                       ("windows", ("window", "windows")))]
    require(focused_display(after_switch[2][1]) == 0,
            "Overview toggle did not retain native phone display focus")
    after_tis = read("after-switch-tis.txt", PHONE_TIS_DUMP)
    after_tis_state = phone_tis_state(after_tis[1])
    after_log = overview_logs[1]
    overview_reads = [read("overview-%02d.xml" % attempt, hierarchy=True)
                      for attempt in attempts(r"overview-(\d{2})\.xml")]
    phone_overview(overview_reads[-1][1])
    ordered = [resolve_index, home, *(row[0] for row in home_reads),
               *(row[0] for row in before), tap,
               *(row[0] for attempt in focus for row in attempt), before_tis[0], before_log[0], switch,
               *(row[0] for row in after_switch),
               after_tis[0], after_log[0],
               *(row[0] for row in overview_reads)]
    require(ordered == sorted(set(ordered)) and
            all(attempt[0][0] + 1 == attempt[1][0] and
                attempt[1][0] + 1 == attempt[2][0] for attempt in [before, *focus, after_switch]) and
            before_tis[0] + 1 == before_log[0] and before_log[0] + 1 == switch and
            after_switch[-1][0] + 1 == after_tis[0] and after_tis[0] + 1 == after_log[0],
            "Phone focus/one-toggle/Overview chronology is missing or reordered")
    input_indices = {index for index in range(home, overview_reads[-1][0])
                     if command_argv(trace[index])[:len(shell) + 1] == shell + ["input"]}
    require(input_indices == {home, tap, switch},
            "An extra input or repeated toggle altered phone Overview entry")
    floor = 0
    for row in trace[resolve_index:overview_reads[-1][0] + 2]:
        started, ended = row.get("started_monotonic_ns"), row.get("ended_monotonic_ns")
        require(type(started) is int and type(ended) is int and 0 < started <= ended and
                floor <= started, "Phone Overview command timings are malformed or reordered")
        floor = ended
    times = (trace[resolve_index].get("started_monotonic_ns"),
             trace[overview_reads[-1][0] + 1].get("ended_monotonic_ns"))
    require(all(type(value) is int and value > 0 for value in times) and
            0 <= times[1] - times[0] < PHONE_OVERVIEW_TIMEOUT_NS,
            "Phone focus/Overview proof exceeded its bounded deadline")
    return {"home": home, "tap": tap, "switch": switch,
            "overview": overview_reads[-1][0], "tis_before": before_tis_state,
            "tis_after": after_tis_state, "overview_logs": [before_log[0], after_log[0]]}


def validate_input_inventory(trace: list, report: dict, stages: dict, directory: Path):
    """Consume every input command as one bounded, evidence-derived UI action.

    Exact semantic checks below prove the effects of the important actions.
    This inventory supplies the complementary negative proof: there was no
    unreported key, pointer action, shortcut, or second tap which actually
    caused the observed transition.
    """
    shell = ["docker", "exec", report["container_id"], "adb", "-s", SERIAL, "shell"]
    consumed = set()

    def exact(low, high, suffix, label):
        rows = [index for index in range(low, high)
                if command_argv(trace[index]) == shell + list(map(str, suffix)) and
                trace[index].get("returncode") == 0]
        require(len(rows) == 1, "Input inventory lacks one exact " + label)
        require(rows[0] not in consumed, "One input was reused for two scenario actions")
        consumed.add(rows[0])
        return rows[0]

    def evidence_index(stage, relative):
        rows = [index for index in range(stage["trace_start"], stage["trace_end"])
                if trace[index].get("evidence") == relative]
        require(len(rows) == 1, "Input anchor evidence is missing/ambiguous: " + relative)
        return rows[0]

    # Each new scenario task is launched through exactly one HOME -> All Apps
    # traversal and one tap derived from the separately sealed drawer dump.
    launch_taps = {}
    for stage_name, components in LAUNCH_PLAN.items():
        stage = stages[stage_name]
        anchors = []
        for ordinal, component in enumerate(components):
            relative = "launches/%02d-%s-%d.xml" % (
                STAGES.index(stage_name), stage_name, ordinal)
            anchors.append((component, relative, evidence_index(stage, relative)))
        selection = report["stages"][STAGES.index(stage_name)]["selection"]
        boundary = (evidence_index(stage, selection) if selection is not None else
                    evidence_index(stage,
                        report["stages"][STAGES.index(stage_name)]["files"]["activities"]))
        previous = stage["trace_start"]
        for ordinal, (component, relative, hierarchy_index) in enumerate(anchors):
            high = anchors[ordinal + 1][2] if ordinal + 1 < len(anchors) else boundary
            point = launcher_icon(stable_bytes(literal_child(directory, relative)).decode("utf-8"),
                                  LABELS[component])
            tap = exact(hierarchy_index + 1, high,
                        ["input", "touchscreen", "-d", "0", "tap", *point],
                        "sealed All Apps icon tap")
            home = exact(previous, hierarchy_index,
                         ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"],
                         "pre-launch HOME")
            drawer = exact(home + 1, hierarchy_index,
                           ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_ALL_APPS"],
                           "All Apps key")
            require(drawer < hierarchy_index < tap,
                    "Ordinary launcher input order changed")
            scroll = shell + ["input", "touchscreen", "-d", "0", "swipe",
                              "540", "2050", "540", "650", "450"]
            scrolls = [index for index in range(drawer + 1, hierarchy_index)
                       if command_argv(trace[index]) == scroll and
                       trace[index].get("returncode") == 0]
            require(len(scrolls) <= 7,
                    "All Apps search escaped its bounded drawer scroll budget")
            for index in scrolls:
                require(index not in consumed, "Drawer scroll was reused")
                consumed.add(index)
            previous = tap + 1
            launch_taps.setdefault(stage_name, []).append(tap)

    # Prove normal Home and genuine native phone focus before the sole toggle,
    # then actual Overview before the exact sealed task chip.  No blind swipes.
    menu_chip_taps = {}
    for stage_name in SELECTION_STAGES:
        stage = stages[stage_name]
        selection = report["stages"][STAGES.index(stage_name)]["selection"]
        selection_index = evidence_index(stage, selection)
        start = (launch_taps.get(stage_name, [stage["trace_start"] - 1])[-1] + 1)
        phone = validate_phone_overview_trace(trace, report["container_id"], directory,
                                              stage_name, start, selection_index)
        require(not ({phone["home"], phone["tap"], phone["switch"]} & consumed),
                "Phone Overview input was reused")
        consumed.update((phone["home"], phone["tap"], phone["switch"]))
        switch = phone["switch"]
        phone_overview(stages[stage_name]["raw"]["selection"])
        component = COMPONENTS["unavailable"] if stage_name == "unavailable" else \
                    LAUNCH_PLAN[stage_name][0]
        chip = recents_card(stages[stage_name]["raw"]["selection"], RECENTS_LABELS[component])[0]
        capture_start = evidence_index(stage,
            report["stages"][STAGES.index(stage_name)]["files"]["activities"])
        chip_index = exact(selection_index + 1, capture_start,
                           ["input", "touchscreen", "-d", "0", "tap", *chip],
                           "sealed Recents task-menu chip tap")
        require(switch < selection_index < chip_index,
                "Recents menu input order changed")
        menu_chip_taps[stage_name] = chip_index

    # Destination focus uses a physical mouse tap at the exact connector
    # centre.  The semantic audit separately binds it to the resulting Window
    # Manager and broker focus observation.
    for stage_name, slot in {
            "transfer_1_menu": 1, "transfer_2_menu": 2, "transfer_3_menu": 3,
            "selected_display_menu": 2, "same_slot_menu": 3,
            "screenshot_menu": 1}.items():
        stage = stages[stage_name]
        display = [row for row in stage["displays"].values() if row["slot"] == slot]
        require(len(display) == 1, "Input inventory cannot resolve focused connector")
        row = display[0]
        exact(stage["trace_start"], menu_chip_taps[stage_name],
              ["input", "mouse", "-d", row["display"], "tap",
               row["width"] // 2, row["height"] // 2],
              "external-display mouse focus")

    # Consume the one explicit state-changing input for every claimed action.
    exact(stages["cancelled"]["trace_start"], stages["cancelled"]["trace_end"],
          ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_BACK"],
          "Recents BACK cancellation")

    removal = stages["task_remove_card"]
    start = launch_taps["task_remove_card"][-1] + 1
    phone = validate_phone_overview_trace(trace, report["container_id"], directory,
                                          "task_remove_card", start, removal["trace_end"])
    require(not ({phone["home"], phone["tap"], phone["switch"]} & consumed),
            "Phone removal Overview input was reused")
    consumed.update((phone["home"], phone["tap"], phone["switch"]))
    phone_overview(removal["raw"]["hierarchy"])
    _, box = recents_card(removal["raw"]["hierarchy"],
                          RECENTS_LABELS[COMPONENTS["removed"]], chip=False)
    x, y = (box[0] + box[2]) // 2, (box[1] + box[3]) // 2
    exact(removal["trace_start"], removal["trace_end"],
          ["input", "touchscreen", "-d", "0", "swipe", x, y, x, 120, 500],
          "exact Recents task-removal swipe")

    for slot in (1, 2, 3):
        name = "transfer_%d_menu" % slot
        point = launcher_control(stages[name]["raw"]["hierarchy"], "Send to Wonad")
        exact(menu_chip_taps[name] + 1, stages[name]["trace_end"],
              ["input", "touchscreen", "-d", "0", "tap", *point],
              "Send-to-Wonad transfer tap")

    for name, source in (("selected_display_rejected", "selected_display_menu"),
                         ("same_slot_rejected", "same_slot_menu")):
        stage = stages[name]
        point = launcher_control(stages[source]["raw"]["hierarchy"], "Send to Wonad")
        tap = exact(stage["trace_start"], stage["trace_end"],
                    ["input", "touchscreen", "-d", "0", "tap", *point],
                    "stale Send-to-Wonad rejection tap")
        home = exact(tap + 1, stage["trace_end"],
                     ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"],
                     "post-rejection HOME")
        checkpoints = []
        for index in range(home + 1, stage["trace_end"]):
            tail = command_argv(trace[index])[len(shell):]
            if len(tail) == 8 and tail[:5] == ["dumpsys", "activity", "service",
                    APP + "/.ConformanceService", "runtime-command"] and \
                    tail[5] == report["conformance_run"] and \
                    RUN_ID.fullmatch(tail[6]) and tail[7] == "checkpoint" and \
                    trace[index].get("returncode") == 0:
                checkpoints.append(index)
        require(len(checkpoints) == 1,
                "Stale rejection lacks one post-action runtime checkpoint: " + name)
        relative_log = report["stages"][STAGES.index(name)]["files"]["log"]
        require_stage_log_after(trace, stage, relative_log,
                                [tap, home, checkpoints[0]], name)

    point = launcher_control(stages["screenshot_menu"]["raw"]["hierarchy"], "Screenshot")
    exact(menu_chip_taps["screenshot_menu"] + 1, stages["screenshot_menu"]["trace_end"],
          ["input", "touchscreen", "-d", "0", "tap", *point],
          "stock Screenshot tap")

    point = launcher_control(stages["split_menu"]["raw"]["hierarchy"], "Split screen")
    exact(menu_chip_taps["split_menu"] + 1, stages["split_menu"]["trace_end"],
          ["input", "touchscreen", "-d", "0", "tap", *point],
          "stock Split-screen tap")
    point = recents_card(stages["split_select"]["raw"]["hierarchy"],
                         RECENTS_LABELS[COMPONENTS["split_secondary"]], chip=False)[0]
    exact(stages["split_select"]["trace_start"], stages["split_select"]["trace_end"],
          ["input", "touchscreen", "-d", "0", "tap", *point],
          "split-screen second-task tap")

    return require_consumed_input_inventory(trace, shell, consumed)


def runtime_control_rows(trace: list, service_argv: list[str], run: str):
    prefix = service_argv + ["runtime-command"]
    rows = [(index, row) for index, row in enumerate(trace)
            if command_argv(row)[:len(prefix)] == prefix]
    require(all(len(command_argv(row)) == len(prefix) + 3 and
                command_argv(row)[-3] == run and
                RUN_ID.fullmatch(command_argv(row)[-2]) is not None and
                command_argv(row)[-1] in {"checkpoint", "stop"}
                for _, row in rows),
            "Foreign, malformed, copy or reopen runtime control escaped review")
    return rows


def bind_runtime_control(row: dict, run: str, phase: str, status: dict,
                         seen_nonces: set[str]) -> str:
    argv = command_argv(row)
    nonce = argv[-2] if len(argv) >= 2 else ""
    marker = "WONAD_CONFORMANCE_CONTROL accepted %s %s %s" % (run, nonce, phase)
    require(RUN_ID.fullmatch(nonce) is not None and nonce not in seen_nonces and
            row.get("returncode") == 0 and isinstance(row.get("output"), str) and
            sum(line.strip() == marker for line in row["output"].splitlines()) == 1 and
            status["handshake"] == {"nonce": nonce, "phase": phase, "result": "accepted"},
            "Runtime control marker/status nonce is missing, replayed, or unbound")
    return nonce


def accepted_ready_observation(value: dict, run: str, nonce: str, phase: str,
                               display_ids: set[int] | None = None) -> bool:
    snapshot = value.get("snapshot")
    valid = (value.get("run") == run and value.get("handshake") == {
        "nonce": nonce, "phase": phase, "result": "accepted"} and
        value.get("state") == value.get("phase") == "ready" and
        value.get("runtime_readiness") == {"ready": True, "session_open": True,
                                            "reopen_required": False} and
        value.get("failure") is None and value.get("control_error") is None and
        value.get("revocation_reason") is None and isinstance(snapshot, dict) and
        snapshot.get("interaction_blocked") is False and
        all(row.get("shell_generation") == snapshot.get("generation")
            for row in snapshot.get("display_incarnations", [])))
    if valid and display_ids is not None:
        valid = {row["display_id"] for row in snapshot["display_incarnations"]} == display_ids
    return valid


def validate_control_completion(controls: list, seen_controls: set[int], finish_sequence: int):
    stops = [index for index, row in controls if command_argv(row)[-1] == "stop"]
    require({index for index, _ in controls} == seen_controls and len(stops) == 1 and
            stops[0] == max(seen_controls) and finish_sequence > stops[0],
            "Unexpected runtime mutation or stop ordering escaped reviewed stages")
    return True


def validate_trace(trace: list, report: dict, stages: dict, directory: Path):
    require(isinstance(trace, list) and trace, "Missing producer command trace")
    container = report["container_id"]
    previous_sequence = -1
    timeline_floor = 0
    for row in trace:
        keys = set(row) if isinstance(row, dict) else set()
        require(isinstance(row, dict) and keys in (
            {"sequence", "kind", "argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "output"},
            {"sequence", "kind", "argv", "returncode", "started_monotonic_ns", "ended_monotonic_ns", "evidence", "output_sha256"},
            {"sequence", "kind", "id", "argv", "started_monotonic_ns"},
            {"sequence", "kind", "id", "returncode", "ended_monotonic_ns", "evidence", "output_sha256"},
            {"sequence", "kind", "inputs", "evidence", "output_sha256"},
        ) and type(row["sequence"]) is int and row["sequence"] == previous_sequence + 1,
                "Malformed/reordered producer trace")
        previous_sequence = row["sequence"]
        if "argv" in row and "returncode" in row:
            require(row.get("kind") == "command" and type(row["returncode"]) is int and
                    type(row["started_monotonic_ns"]) is int and
                    type(row["ended_monotonic_ns"]) is int and
                    0 < row["started_monotonic_ns"] and
                    timeline_floor <= row["started_monotonic_ns"] <= row["ended_monotonic_ns"],
                    "Malformed command timing/type in producer trace")
            timeline_floor = row["ended_monotonic_ns"]
        elif keys == {"sequence", "kind", "id", "argv", "started_monotonic_ns"}:
            require(row.get("kind") == "background_start" and
                    type(row["started_monotonic_ns"]) is int and
                    row["started_monotonic_ns"] > 0 and
                    row["started_monotonic_ns"] >= timeline_floor,
                    "Malformed instrumentation start trace")
            timeline_floor = row["started_monotonic_ns"]
        elif keys == {"sequence", "kind", "id", "returncode", "ended_monotonic_ns", "evidence", "output_sha256"}:
            require(row.get("kind") == "background_finish" and type(row["returncode"]) is int and
                    type(row["ended_monotonic_ns"]) is int and
                    row["ended_monotonic_ns"] >= timeline_floor,
                    "Malformed instrumentation finish trace")
            timeline_floor = row["ended_monotonic_ns"]
        elif keys == {"sequence", "kind", "inputs", "evidence", "output_sha256"}:
            require(row.get("kind") == "derived", "Malformed derived trace kind")
        else:
            raise EvidenceError("Trace row kind does not match its exact schema")
        if row.get("kind") == "derived":
            package_identity_derivation(trace, row, report["evidence_files"], directory, container)
            continue
        if "evidence" in row:
            relative = row["evidence"]
            require(relative in report["evidence_files"] and
                    row["output_sha256"] == sha256(literal_child(directory, relative)),
                    "Trace output differs from sealed evidence")
        if "argv" not in row:
            continue
        argv = row["argv"]
        reviewed_command(argv)
        if argv[:2] == ["docker", "exec"]:
            require(len(argv) >= 5 and argv[2] == container, "Producer addressed a foreign container")
        if argv[:2] == ["docker", "container"]:
            require(argv[3] == container, "Producer inspected a foreign container")

    identity = "instrumentation-" + report["conformance_run"]
    instrument_prefix = ["docker", "exec", container, "adb", "-s", SERIAL, "shell", "am",
        "instrument", "-w", "-r", "-e", "run", report["conformance_run"], "-e", "mode",
        "runtime", "-e", "nonce"]
    starts = [row for row in trace if row.get("kind") == "background_start"]
    finishes = [row for row in trace if row.get("kind") == "background_finish"]
    start_argv = starts[0].get("argv", []) if len(starts) == 1 else []
    initial_nonce = start_argv[len(instrument_prefix)] if len(start_argv) > len(instrument_prefix) else ""
    expected_instrument = instrument_prefix + [initial_nonce, "-e", "phase", "start",
                                               APP + "/.ConformanceInstrumentation"]
    require(len(starts) == len(finishes) == 1 and starts[0]["id"] == finishes[0]["id"] == identity and
            RUN_ID.fullmatch(initial_nonce) is not None and start_argv == expected_instrument and
            finishes[0]["returncode"] == 0 and
            finishes[0]["evidence"] == "identity/instrumentation.txt" and
            starts[0]["sequence"] < finishes[0]["sequence"] and
            starts[0]["started_monotonic_ns"] < finishes[0]["ended_monotonic_ns"],
            "Instrumentation background lifetime is missing/ambiguous")
    try:
        instrument_output = stable_bytes(literal_child(
            directory, "identity/instrumentation.txt")).decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvidenceError("Runtime instrumentation output is not UTF-8") from error
    instrumentation_success(instrument_output, report["conformance_run"])
    validate_identity_trace(trace, report, stages)
    protected_process_epochs(trace, report, stages)

    # The only direct ActivityManager launches are the two declared setup
    # fixtures which seed the runtime catalogue.  Scenario tasks themselves
    # must come through the genuine Launcher path audited below.
    shell_argv = ["docker", "exec", container, "adb", "-s", SERIAL, "shell"]
    start_prefix = shell_argv + ["am", "start"]
    direct_starts = [(index, row) for index, row in enumerate(trace)
                     if command_argv(row)[:len(start_prefix)] == start_prefix]
    baseline_slots = {row["slot"]: row["display"]
                      for row in stages["baseline"]["displays"].values()}
    require(set(baseline_slots) == {1, 2, 3},
            "Baseline lacks the exact three setup connector slots")
    expected_starts = [
        start_prefix + ["-W", "--display", str(baseline_slots[slot]), "-n",
                        FIXTURE + "/" + activity]
        for slot, activity in ((1, ".OneActivity"), (2, ".TwoActivity"))
    ]
    require([command_argv(row) for _, row in direct_starts] == expected_starts and
            all(row.get("returncode") == 0 and index < starts[0]["sequence"]
                for index, row in direct_starts),
            "Direct ActivityManager launch escaped the two exact setup fixtures")
    all_am = [row for row in trace
              if command_argv(row)[:len(shell_argv) + 1] == shell_argv + ["am"]]
    allowed_am = [shell_argv + ["am", "get-current-user"], *expected_starts,
                  expected_instrument]
    require(len(all_am) == len(allowed_am) and
            all(sum(command_argv(row) == expected for row in all_am) == 1
                for expected in allowed_am),
            "Extra ActivityManager launch/instrumentation escaped review")

    emulator_prefix = shell_argv[:6] + ["emu", "multidisplay"]
    topology_commands = [(index, row) for index, row in enumerate(trace)
                         if command_argv(row)[:len(emulator_prefix)] == emulator_prefix]
    expected_topology = [
        emulator_prefix + ["add", str(slot), *map(str, DISPLAY_SPECS[slot]), "132165"]
        for slot in (1, 2, 3)
    ] + [
        emulator_prefix + ["del", "2"],
        emulator_prefix + ["del", "3"],
        emulator_prefix + ["add", "3", *map(str, DISPLAY_SPECS[3]), "132165"],
    ]
    require([command_argv(row) for _, row in topology_commands] == expected_topology and
            all(row.get("returncode") == 0 and isinstance(row.get("output"), str) and
                "OK" in row["output"] and "KO:" not in row["output"]
                for _, row in topology_commands),
            "Unreviewed/transient emulator display hotplug escaped the scenario")

    # UIAutomator is allowed only as a fresh dump immediately read and removed.
    dump_prefix = shell_argv + ["uiautomator", "dump"]
    for index, row in enumerate(trace):
        argv = command_argv(row)
        if argv[:len(dump_prefix)] != dump_prefix:
            continue
        require(len(argv) == len(dump_prefix) + 1 and index + 2 < len(trace),
                "Malformed UIAutomator dump command")
        remote = argv[-1]
        cat = trace[index + 1]
        require(command_argv(cat) == shell_argv[:6] + ["exec-out", "cat", remote],
                "UIAutomator dump was not immediately read")
        validate_hierarchy_lifecycle(trace, cat, container, remote)

    # Every capture range must contain the exact read which produced each raw
    # file.  A file written out of band or copied from another stage cannot pass.
    for stage in stages.values():
        low, high = stage["trace_start"], stage["trace_end"]
        require(high <= len(trace), "Capture trace range escapes command journal")
        report_stage = report["stages"][STAGES.index(stage["name"])]
        suffixes = {
            "activities": ["shell", "dumpsys", "activity", "activities"],
            "fixture": ["shell", "dumpsys", "activity", FIXTURE],
            "windows": ["shell", "dumpsys", "window", "windows"],
            "input": ["shell", "dumpsys", "input"],
            "display": ["shell", "dumpsys", "display"],
            "conformance": ["shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"],
            "systemui": ["shell", "dumpsys", "activity", "service", SYSTEMUI + "/.SystemUIService"],
            "log": ["shell", "logcat", "-b", "main", "-b", "events", "-d", "-v", "threadtime",
                    "-t", "4000"],
        }
        adb_prefix = ["docker", "exec", container, "adb", "-s", SERIAL]
        for kind, relative in report_stage["files"].items():
            rows = [row for row in trace[low:high] if row.get("evidence") == relative]
            require(len(rows) == 1 and rows[0].get("returncode") == 0,
                    "Stage diagnostic lacks one original command read")
            argv = command_argv(rows[0])
            if kind == "hierarchy":
                require(argv[:6] == ["docker", "exec", container, "adb", "-s", SERIAL] and
                        argv[6:8] == ["exec-out", "cat"] and len(argv) == 9 and
                        re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-capture-[0-9a-f]{32}-\d+\.xml",
                                     argv[8]) is not None,
                        "Stage hierarchy did not originate in its exact UIAutomator file")
                validate_hierarchy_lifecycle(trace, rows[0], container, argv[8])
            else:
                require(argv == adb_prefix + suffixes[kind],
                        "Stage diagnostic command differs from its declared kind")
        selection = report_stage["selection"]
        if selection is not None:
            rows = [row for row in trace[low:high] if row.get("evidence") == selection]
            argv = command_argv(rows[0]) if len(rows) == 1 else []
            require(len(rows) == 1 and rows[0].get("returncode") == 0 and
                    argv[:6] == ["docker", "exec", container, "adb", "-s", SERIAL] and
                    argv[6:8] == ["exec-out", "cat"] and len(argv) == 9 and
                    re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml", argv[8]) is not None,
                    "Recents selection lacks one original UIAutomator hierarchy read")
            validate_hierarchy_lifecycle(trace, rows[0], container, argv[8])
        for slot, relative in report_stage["frames"].items():
            validate_frame_trace(trace, low, high, directory, container, int(slot), relative)
    validate_external_copy_inventory(trace, report)
    validate_frame_capture_inventory(trace, report, container)
    validate_log_inventory(trace, report, stages)

    # Every acknowledged runtime instruction is an exact run/nonce/phase
    # handshake.  Pre-Recents checkpoints prove readiness before protected UI;
    # their accepted nonce is merely retained by the blocked capture, not
    # misrepresented as an acknowledgement of that blocked snapshot.
    service_argv = ["docker", "exec", container, "adb", "-s", SERIAL, "shell",
                    "dumpsys", "activity", "service", APP + "/.ConformanceService"]
    control_prefix = service_argv + ["runtime-command"]
    controls = runtime_control_rows(trace, service_argv, report["conformance_run"])
    accepted_start = []
    first_control = controls[0][0] if controls else len(trace)
    for index, row in enumerate(trace[starts[0]["sequence"] + 1:first_control],
                                start=starts[0]["sequence"] + 1):
        if command_argv(row) != service_argv or row.get("returncode") != 0 or \
                not isinstance(row.get("output"), str):
            continue
        try:
            value = runtime_status(row["output"])
        except EvidenceError:
            continue
        if accepted_ready_observation(value, report["conformance_run"], initial_nonce,
                                      "start", set(stages["baseline"]["displays"])):
            accepted_start.append((index, row))
    require(accepted_start, "Runtime start nonce lacks an observed accepted readiness handshake")

    preblocked = (SELECTION_STAGES - {"unavailable"}) | {"task_remove_card"}
    expected_control_stages = set(SETTLED_PHASES) | preblocked | {"unavailable"}
    seen_nonces = {initial_nonce}
    seen_controls = set()
    for name in expected_control_stages:
        stage = stages[name]
        phase = "stop" if name == "unavailable" else "checkpoint"
        candidates = [(index, row) for index, row in controls
                      if stage["trace_start"] <= index < stage["trace_end"] and
                      len(command_argv(row)) == len(control_prefix) + 3 and
                      command_argv(row)[-3] == report["conformance_run"] and
                      command_argv(row)[-1] == phase]
        require(len(candidates) == 1, "Stage lacks one exact runtime " + phase + " handshake: " + name)
        index, row = candidates[0]
        nonce = bind_runtime_control(row, report["conformance_run"], phase,
                                     stage["status"], seen_nonces)
        conformance_rows = [(position, candidate) for position, candidate in
                            enumerate(trace[stage["trace_start"]:stage["trace_end"]],
                                      start=stage["trace_start"])
                            if candidate.get("evidence") ==
                               report["stages"][STAGES.index(name)]["files"]["conformance"]]
        require(len(conformance_rows) == 1 and index < conformance_rows[0][0],
                "Runtime handshake is not ordered before its sealed status")
        if name in preblocked:
            switches = [position for position, candidate in enumerate(trace[stage["trace_start"]:stage["trace_end"]],
                                                                       start=stage["trace_start"])
                        if command_argv(candidate) == ["docker", "exec", container, "adb", "-s", SERIAL,
                            "shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_APP_SWITCH"]]
            require(switches and index < min(switches),
                    "Protected-UI checkpoint was not ordered before entering Recents")
            accepted = []
            for position, candidate in enumerate(trace[index + 1:min(switches)], start=index + 1):
                if command_argv(candidate) != service_argv or candidate.get("returncode") != 0 or \
                        not isinstance(candidate.get("output"), str):
                    continue
                try:
                    value = runtime_status(candidate["output"])
                except EvidenceError:
                    continue
                if accepted_ready_observation(value, report["conformance_run"], nonce,
                                              "checkpoint"):
                    live = value["snapshot"]
                    blocked = stage["status"]["snapshot"]
                    require(live["generation"] == blocked["generation"] and
                            live["identity_epoch"] == blocked["identity_epoch"] and
                            live["topology_revision"] == blocked["topology_revision"] and
                            live["revision"] <= blocked["revision"] and
                            live["display_incarnations"] == blocked["display_incarnations"] and
                            live["tasks"] == blocked["tasks"],
                            "Pre-Recents checkpoint differs from the blocked stage session/topology")
                    focus_slots = {
                        "transfer_1_menu": 1, "transfer_2_menu": 2,
                        "transfer_3_menu": 3, "selected_display_menu": 2,
                        "same_slot_menu": 3,
                    }
                    if name in focus_slots:
                        targets = [item["display"] for item in stage["displays"].values()
                                   if item["slot"] == focus_slots[name]]
                        tokens = [item["token"] for item in live["display_incarnations"]
                                  if item["display_id"] in targets]
                        require(len(targets) == len(tokens) == 1 and
                                live["focused_display_token"] == tokens[0],
                                "Accepted checkpoint did not bind the selected broker display")
                    accepted.append(position)
            require(accepted,
                    "Protected-UI checkpoint was not completed before entering Recents")
        seen_nonces.add(nonce); seen_controls.add(index)

    continuation = {
        "cancelled": "cancel_menu",
        "task_removed": "task_remove_card",
        "selected_display_removed": "selected_display_menu",
        "same_slot_removed": "same_slot_menu",
        "same_slot_readded": "same_slot_menu",
        "screenshot_activated": "screenshot_menu",
        "split_select": "split_menu",
    }
    for name, source in continuation.items():
        require(stages[name]["status"]["handshake"] == stages[source]["status"]["handshake"] and
                not any(stages[name]["trace_start"] <= index < stages[name]["trace_end"]
                        for index, _ in controls),
                "Blocked continuation fabricated a new runtime acknowledgement")
    validate_control_completion(controls, seen_controls, finishes[0]["sequence"])

    # A final Home capture alone cannot prove that a stale task-menu action
    # dismissed itself.  Bind the tap to the first genuine UIAutomator read
    # which shows that Send is absent, and require that observation before
    # HOME and the settled checkpoint.
    for name, source in (("selected_display_rejected", "selected_display_menu"),
                         ("same_slot_rejected", "same_slot_menu")):
        stage = stages[name]
        point = launcher_control(stages[source]["raw"]["hierarchy"], "Send to Wonad")
        tap_argv = shell_argv + ["input", "touchscreen", "-d", "0", "tap",
                                 *map(str, point)]
        home_argv = shell_argv + ["input", "keyboard", "-d", "0", "keyevent",
                                  "KEYCODE_HOME"]
        taps = [index for index in range(stage["trace_start"], stage["trace_end"])
                if command_argv(trace[index]) == tap_argv and
                trace[index].get("returncode") == 0]
        homes = [index for index in range(stage["trace_start"], stage["trace_end"])
                 if command_argv(trace[index]) == home_argv and
                 trace[index].get("returncode") == 0]
        checkpoints = [index for index, row in controls
                       if stage["trace_start"] <= index < stage["trace_end"] and
                       command_argv(row)[-1] == "checkpoint"]
        require(len(taps) == len(homes) == len(checkpoints) == 1 and
                taps[0] < homes[0] < checkpoints[0],
                "Stale action lacks exact tap, dismissal, HOME, checkpoint order")
        absent_reads = []
        for index in range(taps[0] + 1, homes[0]):
            argv = command_argv(trace[index])
            if argv[:6] != shell_argv[:6] or argv[6:8] != ["exec-out", "cat"] or len(argv) != 9:
                continue
            remote = argv[8]
            if re.fullmatch(r"/data/local/tmp/wonad-phase1-recents-[0-9a-f]{16}\.xml",
                            remote) is None or trace[index].get("returncode") != 0 or \
                    not isinstance(trace[index].get("output"), str):
                continue
            try:
                absent = launcher_control(trace[index]["output"], "Send to Wonad",
                                          required=False) is None
            except (EvidenceError, ET.ParseError):
                continue
            if absent:
                validate_hierarchy_lifecycle(trace, trace[index], container, remote)
                absent_reads.append(index)
        require(len(absent_reads) == 1 and taps[0] < absent_reads[0] < homes[0],
                "Stale action dismissal lacks one ordered live no-Send hierarchy")

    current_run_seen = False
    for row in trace[starts[0]["sequence"] + 1:finishes[0]["sequence"]]:
        if command_argv(row) != service_argv or row.get("returncode") != 0 or \
                not isinstance(row.get("output"), str):
            continue
        try:
            value = runtime_status(row["output"])
        except EvidenceError:
            require(not current_run_seen,
                    "Active runtime trace reverted to an unparseable/one-shot ledger")
            continue
        if value["run"] != report["conformance_run"]:
            require(not current_run_seen,
                    "Active runtime trace switched to a foreign conformance run")
            continue
        current_run_seen = True
        require(value["state"] != "failed" and value["handshake"]["result"] != "rejected" and
                value["failure"] is None and value["control_error"] is None and
                value["revocation_reason"] is None,
                "Active runtime trace contains a foreign/failing/rejected ledger")
    require(current_run_seen, "Active runtime trace never exposed its current run")
    validate_launcher_launches(trace, report, stages, directory)
    validate_input_inventory(trace, report, stages, directory)


def exact_adb_prefix(trace: list) -> list[str]:
    prefixes = {tuple(command_argv(row)[:6]) for row in trace
                if len(command_argv(row)) >= 6 and command_argv(row)[:2] == ["docker", "exec"] and
                command_argv(row)[3:6] == ["adb", "-s", SERIAL]}
    require(len(prefixes) == 1, "Command trace has no unique exact adb/container boundary")
    return list(next(iter(prefixes)))


def trace_command(trace, stage: dict, suffix: list[str]):
    low, high = stage["trace_start"], stage["trace_end"]
    expected = exact_adb_prefix(trace) + ["shell", *map(str, suffix)]
    rows = [row for row in trace[low:high] if command_argv(row) == expected and
            row.get("returncode") == 0]
    require(len(rows) == 1, "Missing/ambiguous ordered genuine input action: " + " ".join(map(str, suffix)))
    return rows[0]


def require_ordered(trace: list, first: dict, second: dict, message: str):
    require(next(index for index, row in enumerate(trace) if row is first) <
            next(index for index, row in enumerate(trace) if row is second), message)


def trace_emulator_command(trace, stage: dict | None, suffix: list[str], *, before=None):
    low, high = ((0, len(trace)) if stage is None else
                 (stage["trace_start"], stage["trace_end"]))
    if before is not None:
        high = min(high, before)
    expected = exact_adb_prefix(trace) + list(map(str, suffix))
    rows = [row for row in trace[low:high]
            if command_argv(row) == expected and
            row.get("returncode") == 0 and isinstance(row.get("output"), str) and
            "OK" in row["output"] and "KO:" not in row["output"]]
    require(len(rows) == 1,
            "Missing/ambiguous genuine emulator topology action: " + " ".join(map(str, suffix)))
    return rows[0]


def selected_external_display(trace: list, stage: dict, display: dict):
    tap = trace_command(trace, stage, ["input", "mouse", "-d", str(display["display"]), "tap",
                                      str(display["width"] // 2), str(display["height"] // 2)])
    tap_index = next(index for index, row in enumerate(trace) if row is tap)
    expected = exact_adb_prefix(trace) + ["shell", "dumpsys", "window", "windows"]
    reads = []
    for row in trace[tap_index + 1:stage["trace_end"]]:
        if command_argv(row) != expected or \
                row.get("returncode") != 0 or not isinstance(row.get("output"), str):
            continue
        try:
            if focused_display(row["output"]) == display["display"]:
                reads.append(row)
        except EvidenceError:
            pass
    require(len(reads) == 1,
            "Selected destination lacks one ordered authoritative focus observation")
    return reads[0]


def require_menu(stage: dict, component: str, trace: list, *, send=True):
    xml = stage["raw"]["hierarchy"]
    require(launcher_control(xml, "Screenshot") is not None and
            launcher_control(xml, "Split screen") is not None,
            "Recents lost the stock Screenshot/Split-screen controls")
    point = launcher_control(xml, "Send to Wonad", required=send)
    if not send:
        require(point is None, "Unavailable Recents still advertises Send to Wonad")
    require(component in stage["records"], "Menu is not tied to its exact live task")
    selection = stage["raw"].get("selection")
    require(isinstance(selection, str), "Task menu lacks its pre-open Recents card evidence")
    chip, _ = recents_card(selection, RECENTS_LABELS[component])
    trace_command(trace, stage,
                  ["input", "touchscreen", "-d", "0", "tap", *map(str, chip)])
    return point


def unchanged_incarnations(before: dict, after: dict, slots: set[int]):
    for slot in slots:
        left_display = [value for value in before["displays"].values() if value["slot"] == slot]
        right_display = [value for value in after["displays"].values() if value["slot"] == slot]
        left = [value for value in before["shells"].values() if value["slot"] == slot]
        right = [value for value in after["shells"].values() if value["slot"] == slot]
        left_home = [value for value in before["homes"].values() if value["slot"] == slot]
        right_home = [value for value in after["homes"].values() if value["slot"] == slot]
        left_broker = [value for display, value in before["broker_displays"].items()
                       if before["displays"][display]["slot"] == slot]
        right_broker = [value for display, value in after["broker_displays"].items()
                        if after["displays"][display]["slot"] == slot]
        require(len(left_display) == len(right_display) == len(left) == len(right) ==
                len(left_home) == len(right_home) == len(left_broker) == len(right_broker) == 1 and
                left_display[0] == right_display[0] and left[0] == right[0] and
                left_home[0] == right_home[0] and left_broker[0] == right_broker[0],
                "Unrelated monitor/session incarnation changed")


def audit_external_survivors(stages: dict, fixture_uid: int):
    """Bind every retained broker task to its original native task and pixels.

    A stable broker token alone is not proof that the Android Task survived:
    the app could have died/restarted while a stale catalogue row remained.
    Anchor each lifetime at its setup/transfer observation, then rejoin the
    Task, ActivityRecord, drawn window, input handle and spatial framebuffer
    palette at every subsequent stage until the owning connector is removed.
    DesktopTask tokens are intentionally opaque rather than Android task IDs;
    the bounded proof is therefore relational: one exact native component and
    identity, one live broker token/display/bounds row, and the same spatial
    decoded pixels.  Pinning that token here prevents two same-package tasks
    on one display from exchanging bounds while evading per-token chronology.
    """
    for component, (first, last) in EXTERNAL_SURVIVOR_LIFETIMES.items():
        anchor = stages[first]
        require(component in anchor["records"],
                "External survivor lifetime lacks its native anchor")
        destination = anchor["records"][component]["display"]
        anchor_runtime = runtime_task(anchor, component)
        require(anchor_runtime is not None,
                "External survivor lifetime lacks its broker-task anchor")
        broker_token = anchor_runtime["token"]
        begin, end = STAGES.index(first), STAGES.index(last)
        for name in STAGES[begin:end + 1]:
            stage = stages[name]
            record = exact_task(anchor, stage, component, destination)
            observed_runtime = runtime_task(stage, component)
            require(observed_runtime is not None and observed_runtime["token"] == broker_token,
                    "External survivor changed its opaque broker-task lifetime")
            token = task_window(stage, component, record["task"], destination,
                                fixture_uid, stage["identities"][component])
            task_input(stage, component, fixture_uid, destination, token)
            display = stage["displays"].get(destination)
            require(display is not None and display["slot"] in stage["frames"],
                    "External survivor lost its exact live connector/frame")
            require_fixture_colors(stage["frames"][display["slot"]], component, record)
    return True


def task_move_events(stage: dict, task: int) -> list[tuple[int, int, int, int, int]]:
    values = [tuple(map(int, match)) for match in re.findall(
        r"\bwm_task_moved\s*:\s*\[\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(-?\d+)\s*\]",
        stage["raw"]["log"])]
    return [row for row in values if row[0] == task]


def audit_runtime_chronology(stages: dict):
    """Prove one bounded long-lived runtime without claiming one-shot API coverage."""
    baseline = stages["baseline"]
    baseline_status = baseline["status"]
    baseline_snapshot = baseline_status["snapshot"]
    require(set(item["slot"] for item in baseline["displays"].values()) == {1, 2, 3},
            "Baseline does not contain the three mixed physical connector slots")
    previous = None

    def by_slot(stage, family):
        if family == "broker_displays":
            rows = [(stage["displays"][display]["slot"], row)
                    for display, row in stage[family].items()]
        else:
            rows = [(row["slot"], row) for row in stage[family].values()]
        require(len(rows) == len({slot for slot, _ in rows}),
                "Runtime topology aliases a connector slot")
        return dict(rows)

    def stable_task_identity(row):
        # A genuine layout pass may update z order and bounds.  Everything
        # which names the broker task/display lifetime remains immutable.
        return {key: value for key, value in row.items()
                if key not in {"z_order", "bounds"}}

    for name in STAGES:
        stage = stages[name]
        status = stage["status"]
        snapshot = status["snapshot"]
        require(status["run"] == baseline_status["run"] and status["mode"] == "runtime" and
                status["one_shot_api_coverage"] == {"mode": "full", "status": "not_run"} and
                status["started_elapsed_ms"] == baseline_status["started_elapsed_ms"] and
                status["api_version"] == baseline_status["api_version"] == 3 and
                status["capabilities"] == baseline_status["capabilities"] > 0 and
                snapshot is not None and snapshot["generation"] == baseline_snapshot["generation"] and
                snapshot["identity_epoch"] == baseline_snapshot["identity_epoch"] and
                status["failure"] is None and status["control_error"] is None and
                status["revocation_reason"] is None,
                "Stage crossed the long-lived runtime/session identity")
        require(set(stage["broker_displays"]) == set(stage["displays"]) and
                set(stage["homes"]) == set(stage["displays"]),
                "Runtime stage lacks exact broker/display/Home topology")
        if name != "unavailable":
            require(set(stage["shells"]) == set(stage["displays"]),
                    "Active runtime lacks one exact shell per live display")
            for display, shell in stage["shells"].items():
                broker = stage["broker_displays"][display]
                require(shell["generation"] == snapshot["generation"] and
                        shell["token"] == broker["token"] and
                        broker["shell_generation"] == snapshot["generation"],
                        "Shell URI does not bind the broker generation/display incarnation")
            if name in BLOCKED_STAGES:
                require(status["state"] == "running" and status["phase"] == "syncing-shells" and
                        status["runtime_readiness"] == {"ready": False, "session_open": True,
                                                         "reopen_required": False} and
                        snapshot["interaction_blocked"] is True,
                        "Protected phone UI lacks its live blocked runtime observation")
            else:
                require(name in SETTLED_PHASES and status["state"] == "ready" and
                        status["phase"] == "ready" and
                        status["runtime_readiness"] == {"ready": True, "session_open": True,
                                                         "reopen_required": False} and
                        snapshot["interaction_blocked"] is False,
                        "Settled capture lacks a ready held runtime session")
        else:
            require(status["state"] == status["phase"] == "stopped" and
                    status["runtime_readiness"] == {"ready": False, "session_open": False,
                                                     "reopen_required": False} and
                    not stage["shells"],
                    "Unavailable stage retains conformance runtime authority")
        if previous is not None:
            prior_status, prior_snapshot = previous["status"], previous["status"]["snapshot"]
            require(status["updated_elapsed_ms"] >= prior_status["updated_elapsed_ms"] and
                    status["heartbeat_count"] >= prior_status["heartbeat_count"] and
                    all(status["callbacks"][key] >= prior_status["callbacks"][key]
                        for key in status["callbacks"]) and
                    status["facades"][:len(prior_status["facades"])] == prior_status["facades"] and
                    snapshot["revision"] >= prior_snapshot["revision"] and
                    snapshot["topology_revision"] >= prior_snapshot["topology_revision"],
                    "Runtime ledger/callback/snapshot chronology regressed")

            previous_slots = by_slot(previous, "displays")
            current_slots = by_slot(stage, "displays")
            removed_slots = set(previous_slots) - set(current_slots)
            added_slots = set(current_slots) - set(previous_slots)
            expected_delta = {
                "selected_display_removed": ({2}, set()),
                "same_slot_removed": ({3}, set()),
                "same_slot_readded": (set(), {3}),
            }.get(name, (set(), set()))
            require((removed_slots, added_slots) == expected_delta,
                    "Display topology changed outside its exact reviewed hotplug")
            if expected_delta == (set(), set()):
                require(snapshot["topology_revision"] == prior_snapshot["topology_revision"] and
                        stage["displays"] == previous["displays"] and
                        stage["broker_displays"] == previous["broker_displays"] and
                        stage["homes"] == previous["homes"],
                        "Display/Home/broker incarnation changed without a hotplug")
                if name != "unavailable":
                    require(stage["shells"] == previous["shells"],
                            "Shell incarnation changed without a hotplug")
            else:
                require(snapshot["topology_revision"] > prior_snapshot["topology_revision"],
                        "Hotplug did not advance the runtime topology revision")
                for family in ("displays", "broker_displays", "homes", "shells"):
                    old_rows, new_rows = by_slot(previous, family), by_slot(stage, family)
                    for slot in set(previous_slots) & set(current_slots):
                        require(old_rows.get(slot) == new_rows.get(slot),
                                "Hotplug changed an unrelated display incarnation")
                if removed_slots:
                    for family in ("displays", "broker_displays", "homes", "shells"):
                        require(not (removed_slots & set(by_slot(stage, family))),
                                "Removed connector retained a native/runtime incarnation")
                if added_slots:
                    for family in ("displays", "broker_displays", "homes", "shells"):
                        require(added_slots <= set(by_slot(stage, family)),
                                "Added connector lacks a complete native/runtime incarnation")

            old_tasks = {row["token"]: row for row in prior_snapshot["tasks"]}
            new_tasks = {row["token"]: row for row in snapshot["tasks"]}
            added, removed = set(new_tasks) - set(old_tasks), set(old_tasks) - set(new_tasks)
            if name in {"transfer_1_done", "transfer_2_done", "transfer_3_done"}:
                require(len(added) == 1 and not removed and
                        all(stable_task_identity(old_tasks[token]) ==
                            stable_task_identity(new_tasks[token]) for token in old_tasks),
                        "Transfer did not append exactly one broker task lifetime")
            elif name in {"selected_display_removed", "same_slot_removed"}:
                slot = next(iter(removed_slots))
                removed_display = previous_slots[slot]["display"]
                display_token = previous["broker_displays"][removed_display]["token"]
                expected_removed = {token for token, row in old_tasks.items()
                                    if row["display_token"] == display_token}
                require(not added and removed == expected_removed and
                        all(stable_task_identity(old_tasks[token]) ==
                            stable_task_identity(new_tasks[token])
                            for token in set(old_tasks) & set(new_tasks)),
                        "Broker task lifetime changed outside the removed display")
            else:
                unchanged = (set(old_tasks) == set(new_tasks) and
                    all(stable_task_identity(old_tasks[token]) ==
                        stable_task_identity(new_tasks[token]) for token in old_tasks))
                if name in {"selected_display_rejected", "same_slot_rejected", "unavailable"}:
                    unchanged = unchanged and old_tasks == new_tasks
                require(unchanged,
                        "Broker task catalogue changed outside transfer/display removal")
        previous = stage
    require(stages["selected_display_removed"]["status"]["snapshot"]["topology_revision"] >
            stages["selected_display_menu"]["status"]["snapshot"]["topology_revision"] and
            stages["same_slot_removed"]["status"]["snapshot"]["topology_revision"] >
            stages["same_slot_menu"]["status"]["snapshot"]["topology_revision"] and
            stages["same_slot_readded"]["status"]["snapshot"]["topology_revision"] >
            stages["same_slot_removed"]["status"]["snapshot"]["topology_revision"],
            "Runtime topology revision did not observe remove/re-add events")
    return baseline_snapshot["generation"]


def audit_semantics(stages: dict, trace: list, uids: dict):
    baseline = stages["baseline"]
    audit_runtime_chronology(stages)
    require(not set(COMPONENTS.values()).intersection(baseline["records"]),
            "Scenario task existed before its ordinary Launcher launch")
    for slot, spec in DISPLAY_SPECS.items():
        trace_emulator_command(trace, None,
            ["emu", "multidisplay", "add", str(slot), *map(str, spec), "132165"],
            before=baseline["trace_start"])

    # The only direct launches are setup fixtures.  Prove their resulting
    # native Task/ActivityRecord/window/input lifetime, broker row and actual
    # framebuffer color on the intended two display incarnations.
    for slot, component in ((1, FIXTURE + "/.OneActivity"),
                            (2, FIXTURE + "/.TwoActivity")):
        targets = [row for row in baseline["displays"].values() if row["slot"] == slot]
        require(len(targets) == 1 and component in baseline["records"],
                "Setup fixture is absent from its exact external connector")
        display_id = targets[0]["display"]
        record = baseline["records"][component]
        require(record["display"] == display_id,
                "Setup fixture landed on the wrong external connector")
        identity = baseline["identities"][component]
        token = task_window(baseline, component, record["task"], display_id,
                            uids[FIXTURE], identity)
        task_input(baseline, component, uids[FIXTURE], display_id, token)
        runtime_task(baseline, component)
        require_fixture_colors(baseline["frames"][slot], component, record)
    audit_external_survivors(stages, uids[FIXTURE])

    # Back cancellation preserves every opaque task identity and leaves it on
    # the phone; a label-only menu is insufficient without the ordered BACK.
    cancel_menu, cancelled = stages["cancel_menu"], stages["cancelled"]
    component = COMPONENTS["cancel"]
    require_menu(cancel_menu, component, trace)
    exact_task(cancel_menu, cancelled, component, 0)
    require(launcher_control(cancelled["raw"]["hierarchy"], "Send to Wonad", required=False) is None,
            "Back did not dismiss the genuine task menu")
    trace_command(trace, cancelled, ["input", "keyboard", "-d", "0", "keyevent", "KEYCODE_BACK"])

    # A task-removal result must remove the app observation and both exact
    # server objects after a swipe derived from the selected card bounds.
    remove_card, removed = stages["task_remove_card"], stages["task_removed"]
    component = COMPONENTS["removed"]
    require(component in remove_card["identities"] and component not in removed["records"] and
            str(remove_card["identities"][component]["task_object"]) not in removed["raw"]["activities"] and
            str(remove_card["identities"][component]["activity_record"]) not in removed["raw"]["activities"],
            "Recents swipe did not remove the exact Task/ActivityRecord")
    removal_record = remove_card["records"][component]
    removal_identity = remove_card["identities"][component]
    removal_token = task_window_handle(remove_card, component, removal_record["task"], 0,
                                       uids[FIXTURE], removal_identity)
    _, box = recents_card(remove_card["raw"]["hierarchy"], RECENTS_LABELS[component], chip=False)
    x = (box[0] + box[2]) // 2
    cleared = trace_command(trace, remove_card, list(LOG_CLEAR))
    swiped = trace_command(trace, remove_card, ["input", "touchscreen", "-d", "0", "swipe",
                                      str(x), str((box[1] + box[3]) // 2), str(x), "120", "500"])
    require_ordered(trace, cleared, swiped, "Removal main log was not cleared before card swipe")
    full = component.replace("/.", "/" + FIXTURE + ".")
    require(re.search(r"\bwm_task_removed\s*:\s*\[\s*" +
                      str(removal_record["task"]) + r"\s*,[^\]\n]+\]",
                      removed["raw"]["log"]) is not None and
            not re.search(r"\bWindow\{" + re.escape(removal_token) + r"\b",
                          removed["raw"]["windows"]) and
            not any(re.search(r"\bname=" + re.escape(removal_token) + r"\b", line) and
                    full in line for line in removed["raw"]["input"].splitlines()),
            "Removed task retained its window/input object or lacks exact removal event")

    # Three distinct phone Tasks must retain native identities, appear in the
    # broker's bounded task catalogue, draw their exact test pixels, and land
    # on the connector incarnation selected through genuine mouse focus.
    for slot in (1, 2, 3):
        before, after = stages[f"transfer_{slot}_menu"], stages[f"transfer_{slot}_done"]
        component = COMPONENTS[f"transfer_{slot}"]
        point = require_menu(before, component, trace)
        target = [row for row in before["displays"].values() if row["slot"] == slot]
        require(len(target) == 1 and before["focused_display"] == 0,
                "Transfer menu is not the genuine focused phone UI")
        destination = target[0]["display"]
        selected_external_display(trace, before, target[0])
        record = exact_task(before, after, component, destination)
        identity = after["identities"][component]
        token = task_window(after, component, record["task"], destination,
                            uids[FIXTURE], identity)
        task_input(after, component, uids[FIXTURE], destination, token)
        broker_task = runtime_task(after, component)
        before_tokens = {row["token"] for row in before["status"]["snapshot"]["tasks"]}
        after_tokens = {row["token"] for row in after["status"]["snapshot"]["tasks"]}
        require(after_tokens - before_tokens == {broker_task["token"]} and
                before_tokens <= after_tokens,
                "Broker catalogue did not add exactly the transferred task token")
        require_fixture_colors(after["frames"][slot], component, record)
        require(after["frames"][slot]["pixels_sha256"] !=
                before["frames"][slot]["pixels_sha256"],
                "Destination pixels did not change after exact task transfer")
        events = task_move_events(after, record["task"])
        require(events and events[-1][1] > 0 and
                events[-1][2:4] == (destination, 1),
                "Transfer lacks a final exact ActivityTaskManager move event")
        cleared = trace_command(trace, before, list(LOG_CLEAR))
        tapped = trace_command(trace, before,
            ["input", "touchscreen", "-d", "0", "tap", *map(str, point)])
        require_ordered(trace, cleared, tapped, "Transfer main log was not cleared before action")
        unchanged_incarnations(before, after, {1, 2, 3})

    # Removing the selected display while two other live destinations remain
    # must reject the stale action without a broker task, move event, or pixel
    # change on either surviving monitor.
    selected = stages["selected_display_menu"]
    selected_removed = stages["selected_display_removed"]
    selected_rejected = stages["selected_display_rejected"]
    component = COMPONENTS["selected_removed"]
    point = require_menu(selected, component, trace)
    chosen = [row for row in selected["displays"].values() if row["slot"] == 2]
    require(len(chosen) == 1 and set(row["slot"] for row in selected_removed["displays"].values()) == {1, 3} and
            launcher_control(selected_removed["raw"]["hierarchy"], "Send to Wonad") == point,
            "Selected-display removal did not retain the exact pending phone action")
    selected_external_display(trace, selected, chosen[0])
    trace_emulator_command(trace, selected_removed, ["emu", "multidisplay", "del", "2"])
    unchanged_incarnations(selected, selected_removed, {1, 3})
    record = exact_task(selected, selected_rejected, component, 0)
    runtime_task(selected_rejected, component, required=False)
    require(not task_move_events(selected_rejected, record["task"]) and
            launcher_control(selected_rejected["raw"]["hierarchy"],
                             "Send to Wonad", required=False) is None and
            selected_removed["status"]["snapshot"]["tasks"] ==
                selected_rejected["status"]["snapshot"]["tasks"],
            "Removed destination failed closed without changing a survivor")
    for slot in (1, 3):
        require_fixture_colors_absent(selected_rejected["frames"][slot], component)
    cleared = trace_command(trace, selected_rejected, list(LOG_CLEAR))
    tapped = trace_command(trace, selected_rejected,
                           ["input", "touchscreen", "-d", "0", "tap", *map(str, point)])
    require_ordered(trace, cleared, tapped, "Rejection main log was not cleared before stale transfer")

    # Same connector slot/uniqueId is not the same incarnation.  Both native
    # Home and broker token/hint lifetimes must turn over before the old action
    # is rejected; a recycled logical display ID cannot make it valid.
    old, absent, readded, rejected = (stages[name] for name in
        ("same_slot_menu", "same_slot_removed", "same_slot_readded", "same_slot_rejected"))
    component = COMPONENTS["same_slot"]
    point = require_menu(old, component, trace)
    old_display = [row for row in old["displays"].values() if row["slot"] == 3]
    new_display = [row for row in readded["displays"].values() if row["slot"] == 3]
    require(len(old_display) == len(new_display) == 1 and
            not any(row["slot"] == 3 for row in absent["displays"].values()) and
            old_display[0]["unique_id"] == new_display[0]["unique_id"],
            "Same-slot remove/re-add topology is not genuine")
    selected_external_display(trace, old, old_display[0])
    trace_emulator_command(trace, absent, ["emu", "multidisplay", "del", "3"])
    trace_emulator_command(trace, readded,
        ["emu", "multidisplay", "add", "3", *map(str, DISPLAY_SPECS[3]), "132165"])
    old_id, new_id = old_display[0]["display"], new_display[0]["display"]
    old_home, new_home = old["homes"].get(old_id), readded["homes"].get(new_id)
    old_broker, new_broker = old["broker_displays"].get(old_id), readded["broker_displays"].get(new_id)
    require(old_home is not None and new_home is not None and
            (old_home["task_object"], old_home["activity_record"]) !=
            (new_home["task_object"], new_home["activity_record"]) and
            old_broker is not None and new_broker is not None and
            old_broker["token"] != new_broker["token"] and
            old_broker["identity_hint"] != new_broker["identity_hint"] and
            readded["shells"].get(new_id, {}).get("token") == new_broker["token"],
            "Same-slot replacement reused a native/broker display incarnation")
    unchanged_incarnations(old, absent, {1})
    unchanged_incarnations(absent, readded, {1})
    require(launcher_control(readded["raw"]["hierarchy"], "Send to Wonad") == point,
            "Same-slot stale action was not retained for the rejection probe")
    record = exact_task(old, rejected, component, 0)
    runtime_task(rejected, component, required=False)
    require(not task_move_events(rejected, record["task"]) and
            launcher_control(rejected["raw"]["hierarchy"],
                             "Send to Wonad", required=False) is None and
            readded["status"]["snapshot"]["tasks"] == rejected["status"]["snapshot"]["tasks"] and
            all(frame["known_colors"].get(color, 0) == 0
                for slot, frame in rejected["frames"].items() if slot in {1, 3}
                for color in FIXTURE_COLORS[component]),
            "Same-slot stale action changed a live monitor or broker task")
    cleared = trace_command(trace, rejected, list(LOG_CLEAR))
    tapped = trace_command(trace, rejected,
                           ["input", "touchscreen", "-d", "0", "tap", *map(str, point)])
    require_ordered(trace, cleared, tapped, "Rejection main log was not cleared before stale transfer")

    # Screenshot needs the exact stock action tap plus independent SystemUI,
    # event-log, and decoded pixel effects.
    screenshot_before, screenshot_after = stages["screenshot_menu"], stages["screenshot_activated"]
    component = COMPONENTS["screenshot"]
    require_menu(screenshot_before, component, trace)
    exact_task(screenshot_before, screenshot_after, component, 0)
    screenshot_point = launcher_control(screenshot_before["raw"]["hierarchy"], "Screenshot")
    cleared = trace_command(trace, screenshot_before, list(LOG_CLEAR))
    tapped = trace_command(trace, screenshot_before,
                           ["input", "touchscreen", "-d", "0", "tap", *map(str, screenshot_point)])
    require_ordered(trace, cleared, tapped, "Screenshot main log was not cleared before stock action")
    screenshot_window(screenshot_after, uids[SYSTEMUI])
    require(screenshot_before["frames"][0]["pixels_sha256"] !=
            screenshot_after["frames"][0]["pixels_sha256"] and
            re.search(r"(?i)(screenshotcontroller|screenshot[_ -]?(?:saved|request|animation)|"
                      r"takeScreenshot|screenshot bitmap provided|capturing screenshot|"
                      r"processing screenshot data)", screenshot_after["raw"]["log"]),
            "Screenshot label/tap lacks actual SystemUI, log and pixel activation")

    # Split-screen needs the exact two taps, retained Task/Activity identities,
    # real multi-window state, two substantial phone regions, drawn windows,
    # move events, and both fixtures' decoded colors.
    split_menu, split_select, split_after = (stages[name] for name in
        ("split_menu", "split_select", "split_activated"))
    primary, secondary = COMPONENTS["split_primary"], COMPONENTS["split_secondary"]
    require_menu(split_menu, primary, trace)
    split_point = launcher_control(split_menu["raw"]["hierarchy"], "Split screen")
    second_point, _ = recents_card(split_select["raw"]["hierarchy"], RECENTS_LABELS[secondary], chip=False)
    cleared = trace_command(trace, split_menu, list(LOG_CLEAR))
    tapped = trace_command(trace, split_menu,
                           ["input", "touchscreen", "-d", "0", "tap", *map(str, split_point)])
    require_ordered(trace, cleared, tapped, "Split main log was not cleared before stock action")
    trace_command(trace, split_select,
                  ["input", "touchscreen", "-d", "0", "tap", *map(str, second_point)])
    split_primary_dump = re.split(r"^ActivityTaskSupervisor state:\s*$",
                                  split_after["raw"]["activities"], maxsplit=1,
                                  flags=re.M)[0]
    for component in (primary, secondary):
        origin = split_menu if component == primary else split_select
        record = exact_task(origin, split_after, component, 0)
        blocks = [block for block in re.split(r"(?=^\s*\* Task\{)", split_primary_dump, flags=re.M)
                  if re.search(r"#" + str(record["task"]) + r"\b", block)]
        require(len(blocks) == 1 and re.search(r"(?i)windowingMode=(?:multi-window|6)", blocks[0]),
                "Split-screen task lacks actual multi-window ActivityTaskManager state")
        token = task_window(split_after, component, record["task"], 0,
                            uids[FIXTURE], split_after["identities"][component])
        task_input(split_after, component, uids[FIXTURE], 0, token)
        events = task_move_events(split_after, record["task"])
        require(events and events[-1][1] > 0 and events[-1][2:4] == (0, 1),
                "Split task lacks a final exact ActivityTaskManager move event")
        require_fixture_colors(split_after["frames"][0], component, record)
    require(remove_card["identities"][COMPONENTS["removed"]]["instance"] !=
            split_after["identities"][secondary]["instance"],
            "Removed task was recycled as the split-screen second task")
    first, second = (split_after["records"][value] for value in (primary, secondary))
    boxes = [(row["left"], row["top"], row["right"], row["bottom"])
             for row in (first, second)]
    require(all(0 <= left < right <= 1080 and 0 <= top < bottom <= 2400 and
                right - left >= 700 and bottom - top >= 600 and
                (right - left) * (bottom - top) >= 1080 * 2400 // 4
                for left, top, right, bottom in boxes),
            "Split-screen task is clipped/tiny/outside the phone")
    overlap_width = max(0, min(first["right"], second["right"]) - max(first["left"], second["left"]))
    overlap_height = max(0, min(first["bottom"], second["bottom"]) - max(first["top"], second["top"]))
    vertical_gap = max(first["top"], second["top"]) - min(first["bottom"], second["bottom"])
    horizontal_gap = max(first["left"], second["left"]) - min(first["right"], second["right"])
    plausible_divider = ((overlap_width >= 700 and 0 <= vertical_gap <= 200) or
                         (overlap_height >= 1600 and 0 <= horizontal_gap <= 200))
    require(overlap_width * overlap_height == 0 and plausible_divider and
            split_menu["frames"][0]["pixels_sha256"] != split_after["frames"][0]["pixels_sha256"],
            "Split-screen lacks two substantial regions, one divider, and changed pixels")

    unavailable = stages["unavailable"]
    component = COMPONENTS["unavailable"]
    exact_task(screenshot_after, unavailable, component, 0)
    runtime_task(unavailable, component, required=False)
    require(require_menu(unavailable, component, trace, send=False) is None,
            "Stopped conformance runtime still advertises a desktop transfer")
    return True


def audit_report(report_path: Path, expected_sha256: str | None = None) -> dict:
    report_path = Path(report_path).absolute()
    require(report_path.parent.resolve(strict=True) == report_path.parent and
            report_path.is_file() and not report_path.is_symlink(),
            "Select one literal Recents report file")
    if expected_sha256 is not None:
        require(SHA256.fullmatch(expected_sha256 or "") and sha256(report_path) == expected_sha256,
                "Recents report differs from its authenticated SHA-256")
    directory = report_path.parent
    report = load_json(report_path)
    required = {"schema", "kind", "scope", "status", "api", "run", "conformance_run",
        "container_id", "image_id", "boot_id", "serial", "fingerprint", "uids",
        "privileged_packages", "producer_source", "auditor_source", "commands", "stages", "gates",
        "runtime_qualified", "qualification_claimed", "evidence_files"}
    require(isinstance(report, dict) and set(report) == required and report["schema"] == SCHEMA and
            report["kind"] == KIND and report["scope"] == SCOPE and report["status"] == "passed" and
            report["api"] == 3 and RUN_ID.fullmatch(str(report["run"])) and
            RUN_ID.fullmatch(str(report["conformance_run"])) and
            re.fullmatch(r"[0-9a-f]{64}", str(report["container_id"])) and
            IMAGE_ID.fullmatch(str(report["image_id"])) and BOOT_ID.fullmatch(str(report["boot_id"])) and
            report["serial"] == SERIAL and isinstance(report["fingerprint"], str) and report["fingerprint"] and
            report["runtime_qualified"] is False and report["qualification_claimed"] is False,
            "Malformed/overclaimed Phase-1 Recents report")
    expected_gates = {name: "passed" for name in (
        "three_mixed_displays", "exact_task_each_destination", "back_cancellation",
        "task_removal", "selected_display_removal_fail_closed", "same_slot_new_incarnation_fail_closed",
        "unavailable_session", "screenshot_activation", "split_screen_two_phone_tasks",
        "protected_process_continuity", "guest_os_and_apk_identity")}
    require(report["gates"] == expected_gates, "Incomplete Recents gate ledger")
    require(isinstance(report["uids"], dict) and set(report["uids"]) == {APP, FIXTURE, LAUNCHER, SYSTEMUI},
            "Malformed package UID summary")

    evidence = report["evidence_files"]
    require(isinstance(evidence, dict) and evidence, "Missing evidence inventory")
    stage_paths = validate_stage_manifest(report["stages"])
    require(report["commands"] == "commands.json", "Command journal path changed")
    fixed_paths = {
        "commands.json", "identity/package-uids.txt", "identity/instrumentation.txt",
        "android/tools/phase1_conformance_recents.py",
        "android/tools/phase1_conformance_recents_acceptance.py",
    }
    require(set(evidence) == stage_paths | launch_evidence_paths() | fixed_paths |
            phone_overview_evidence_paths(evidence),
            "Recents evidence inventory has missing, aliased or undeclared files")
    actual_files = {}
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "Symlink exists in Recents evidence tree")
        if path.is_file() and path != report_path:
            relative = path.relative_to(directory).as_posix()
            actual_files[relative] = file_ref(path)
    require(actual_files == evidence, "Recents evidence inventory/bytes changed")
    for name, source in (("producer", report["producer_source"]), ("auditor", report["auditor_source"])):
        require(isinstance(source, dict) and set(source) == {"path", "sha256", "bytes"} and
                isinstance(source["path"], str) and source["path"].startswith("android/tools/") and
                source["path"].endswith(".py") and source["sha256"] == evidence.get(source["path"], {}).get("sha256") and
                source["bytes"] == evidence.get(source["path"], {}).get("bytes"),
                "Unbound exact " + name + " source")
    require(report["auditor_source"]["path"] ==
            "android/tools/phase1_conformance_recents_acceptance.py" and
            sha256(Path(__file__).resolve()) == report["auditor_source"]["sha256"],
            "Running auditor differs from sealed auditor source")
    producer_path = Path(__file__).resolve().with_name("phase1_conformance_recents.py")
    require(report["producer_source"]["path"] ==
            "android/tools/phase1_conformance_recents.py" and producer_path.is_file() and
            sha256(producer_path) == report["producer_source"]["sha256"],
            "Known producer differs from sealed producer source")

    command_path = literal_child(directory, report["commands"])
    require(report["commands"] in evidence, "Unsealed command trace")
    trace = load_json(command_path)
    # Parse the independently captured package-identity input first.
    uids = package_uids(stable_bytes(literal_child(directory, "identity/package-uids.txt")).decode())
    require(uids == report["uids"], "Package UID summary differs from raw package manager output")
    stages = {row["name"]: stage_from_files(directory, row, evidence, uids)
              for row in report["stages"]}
    validate_trace(trace, report, stages, directory)
    audit_semantics(stages, trace, uids)
    require(all(stage["status"].get("run") == report["conformance_run"] for stage in stages.values()),
            "Stages belong to another conformance run")
    return {"status": "accepted_conformance_recents_not_runtime_or_hardware_qualification",
            "run": report["run"], "conformance_run": report["conformance_run"],
            "image_id": report["image_id"], "boot_id": report["boot_id"],
            "report_sha256": sha256(report_path)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(audit_report(args.report, args.expected_sha256), sort_keys=True))
        return 0
    except (EvidenceError, OSError, UnicodeError, json.JSONDecodeError, ET.ParseError) as error:
        print("phase1_conformance_recents_acceptance.py: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
