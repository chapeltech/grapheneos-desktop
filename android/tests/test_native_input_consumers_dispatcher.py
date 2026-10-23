"""Strict live Dispatcher parsing; synthetic controls are not guest receipts."""
from pathlib import Path
import re
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from native_input_consumers import consumers, dispatcher_windows
from native_shell_smoke import shell_input_handles


def dispatcher_dump(fragment, complete=False, system_pid=657, owner_pid=1234):
    """Wrap existing test-only rows without changing their native fields.

    This is a fixture constructor, never a production parser fallback. Older
    synthetic tests supplied row fragments; the production boundary now
    requires the same section framing as an actual native dumpsys input.
    """
    displays, connections, other = {}, [], []
    next_layer = 7000
    for line in fragment.splitlines():
        if re.match(r"\s*\d+: name=", line):
            display = re.search(r"\bdisplayId=(\d+)(?=,|$)", line)
            if display is None:
                raise ValueError("Synthetic fixture window lacks displayId")
            row = line.split(": ", 1)[1]
            if complete:
                if re.search(r"(?<![\w.])id=", row) is None:
                    row += f", id={next_layer},"; next_layer += 1
                if re.search(r"(?<![\w.])ownerPid=", row) is None:
                    pid = system_pid if re.search(r"\bownerUid=1000(?=,|$)", row) else owner_pid
                    row += f", ownerPid={pid},"
            displays.setdefault(int(display[1]), []).append(row)
        elif re.match(r"\s*\d+: channelName=", line):
            connections.append(line.strip())
        else:
            other.append(line)
    body = ["Input Dispatcher State:", "  TouchStatesByDisplay: <no displays touched>",
            "  CursorStatesByDisplay: <no displays touched by cursor>"]
    for display, rows in displays.items():
        body += [f"  Display: {display}", "    Windows:"]
        body += [f"      {index}: {row}" for index, row in enumerate(rows)]
    body += ["  Connections:", *["    " + row for row in connections], *other]
    return "\n".join(body) + "\n"


def consumer_row():
    return ("0: name=Wonad inactive 2, id=190, displayId=2, "
        "inputConfig=NOT_FOCUSABLE | TRUSTED_OVERLAY, alpha=1, "
        "frame=[0,0][4000,2000], globalScale=1, applicationInfo.token=<null>, "
        "touchableRegion=[0,0][4000,2000], ownerPid=664, ownerUid=1000, "
        "token=0x123, touchOcclusionMode=BLOCK_UNTRUSTED")


CONNECTION = "684: channelName='Wonad inactive 2', status=NORMAL, isFocusMonitor=false, responsive=true"
IMS = ("\nInput Manager Service (Java) State:\n"
    "  Gesture Monitors (implemented as spy windows):\n"
    "    2: name='[Gesture Monitor] edge-swipe', InputChannel token=android.os.BinderProxy@e0c72a7, displayId=2\n")


class DispatcherConsumerSectionTests(unittest.TestCase):
    def raw(self):
        return dispatcher_dump(consumer_row() + "\n" + CONNECTION)

    def check(self, raw):
        return consumers(raw, 2, 4000, 2000, 664)

    def test_only_genuine_current_window_section_is_parsed(self):
        self.assertEqual(1, self.check(self.raw() + IMS)["active"])
        rows, _ = dispatcher_windows(self.raw() + IMS)
        self.assertEqual(1, len(rows))

    def test_headerless_fragment_or_inventory_cannot_supply_windows(self):
        for raw in (consumer_row() + "\n" + CONNECTION, IMS, "Input Dispatcher State:\n" + IMS):
            with self.subTest(raw=raw), self.assertRaises(ValueError): self.check(raw)

    def test_missing_or_duplicate_config_in_any_real_window_fails(self):
        other = consumer_row().replace("name=Wonad inactive 2", "name=Ordinary app").replace("id=190", "id=191").replace("token=0x123", "token=0x124")
        for changed in (other.replace("inputConfig=NOT_FOCUSABLE | TRUSTED_OVERLAY, ", ""),
                other.replace("inputConfig=", "inputConfig=NOT_VISIBLE, inputConfig=")):
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "inputConfig"):
                self.check(dispatcher_dump(consumer_row() + "\n" + changed + "\n" + CONNECTION))

    def test_mandatory_fields_cannot_be_deleted_from_real_nonconsumer_rows(self):
        other = consumer_row().replace("name=Wonad inactive 2", "name=Ordinary app").replace("id=190", "id=191").replace("token=0x123", "token=0x124")
        for name in ("id", "ownerPid", "ownerUid", "displayId", "inputConfig"):
            raw = dispatcher_dump(consumer_row() + "\n" + other + "\n" + CONNECTION)
            first, ordinary = raw.split("      1:", 1)
            changed = first + "      1:" + re.sub(r"(?<![\w.])" + name + r"=[^,]+, ", "", ordinary, count=1)
            with self.subTest(field=name), self.assertRaises(ValueError): self.check(changed)

    def test_dispatcher_rows_outside_windows_never_become_hidden_observations(self):
        row = "      1: " + consumer_row().split(": ", 1)[1]
        for raw in (self.raw() + row + "\n", self.raw().replace("  Connections:", row + "\n  Connections:")):
            with self.subTest(raw=raw), self.assertRaises(ValueError): self.check(raw)

    def test_actual_window_uid_pid_display_id_and_duplicates_fail_closed(self):
        raw = self.raw()
        for changed in (raw.replace("ownerUid=1000", "ownerUid=10180"),
                raw.replace("ownerPid=664", "ownerPid=665"),
                raw.replace("displayId=2", "displayId=0"),
                raw.replace("ownerUid=1000", "ownerUid=1000, ownerUid=1000"),
                raw.replace("      0: name=", "      0 name="),
                raw.replace("      0: name=", "      1: name="),
                raw.replace("      0: name=", "    0: name=")):
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.check(changed)
        duplicate = consumer_row().replace("token=0x123", "token=0x124")
        with self.assertRaisesRegex(ValueError, "Duplicate/foreign"):
            self.check(dispatcher_dump(consumer_row() + "\n" + duplicate + "\n" + CONNECTION))

    def test_duplicate_reordered_or_wrong_display_sections_are_rejected(self):
        raw = self.raw()
        for changed in (raw + raw, raw.replace("    Windows:", "    Windows:\n    Windows:"),
                raw.replace("  Connections:", "  Connections:\n  Connections:"),
                raw.replace("  Display: 2\n    Windows:", "    Windows:\n  Display: 2"),
                raw.replace("  Display: 2", "  Display: 0"),
                raw.replace("  Display: 2", "  Display: 2\n  Display: 2")):
            with self.subTest(changed=changed), self.assertRaises(ValueError): self.check(changed)

    def test_historical_anr_cannot_supply_hide_or_duplicate_current_window(self):
        history = self.raw().replace("Input Dispatcher State:", "Input Dispatcher State at time of last ANR:")
        self.assertEqual(1, self.check(self.raw() + "\n" + history + IMS)["active"])
        live = self.raw().replace("name=Wonad inactive 2", "name=Ordinary app")
        with self.assertRaises(ValueError): self.check(live + "\n" + history)
        no_connection = self.raw().replace(CONNECTION, "")
        with self.assertRaises(ValueError): self.check(no_connection + "\n" + history)

    def test_ims_inventory_cannot_supply_duplicate_or_forged_consumer_connections(self):
        self.assertEqual(1, self.check(self.raw() + IMS + "    " + CONNECTION)["active"])
        with self.assertRaises(ValueError): self.check(self.raw().replace(CONNECTION, "") + IMS + "    " + CONNECTION)

    def touching(self):
        return ("  TouchStatesByDisplay:\n    LogicalDisplayId 2:\n      TouchedWindows:\n"
            "        0: name='Wonad inactive 2', targetFlags=FOREGROUND, forwardingWindowToken=(nil), mDeviceStates=\n"
            "          DeviceId(17):[touchingPointers=[Pointer(id=0, FINGER)], downTimeInTarget=1000000000, hoveringPointers=[], pilferingPointerIds=<none>]\n")

    def touched_dump(self):
        return self.raw().replace("  TouchStatesByDisplay: <no displays touched>\n", self.touching())

    def test_current_touched_target_is_validated_but_never_a_window_or_connection(self):
        raw = self.touched_dump()
        rows, connections = dispatcher_windows(raw)
        self.assertEqual([consumer_row().split(": ", 1)[1]], rows)
        self.assertNotIn("targetFlags", connections)
        self.assertEqual(1, self.check(raw + IMS)["active"])
        # Cursor state uses the same pinned TouchState/TouchedWindow format.
        cursor = self.touching().replace("TouchStatesByDisplay", "CursorStatesByDisplay").replace(
            "touchingPointers=[Pointer(id=0, FINGER)]", "touchingPointers=[]").replace(
            "hoveringPointers=[]", "hoveringPointers=[Pointer(id=0, MOUSE) at (10, 20)]")
        raw = self.raw().replace("  CursorStatesByDisplay: <no displays touched by cursor>\n", cursor)
        self.assertEqual(1, len(dispatcher_windows(raw)[0]))

    def test_current_touch_roots_rows_and_device_states_reject_hostile_grammar(self):
        raw = self.touched_dump()
        changes = [("missing-root", "  TouchStatesByDisplay:\n", ""),
            ("duplicate-root", "  TouchStatesByDisplay:\n", "  TouchStatesByDisplay:\n  TouchStatesByDisplay:\n"),
            ("history-root", "  TouchStatesByDisplay:", "  TouchStatesByDisplay at last ANR:"),
            ("empty-with-rows", "  TouchStatesByDisplay:", "  TouchStatesByDisplay: <no displays touched>"),
            ("wrong-display-grammar", "LogicalDisplayId 2:", "LogicalDisplayId(2):"),
            ("duplicate-display", "    LogicalDisplayId 2:\n", "    LogicalDisplayId 2:\n    LogicalDisplayId 2:\n"),
            ("missing-windows", "      TouchedWindows:\n", ""),
            ("duplicate-windows", "      TouchedWindows:\n", "      TouchedWindows:\n      TouchedWindows:\n"),
            ("ordinal", "        0: name=", "        1: name="),
            ("indent", "        0: name=", "      0: name="),
            ("missing-name", "name='Wonad inactive 2', ", ""),
            ("invented-dispatchmode", "targetFlags=FOREGROUND", "targetFlags=FOREGROUND | AS_IS"),
            ("duplicate-flag", "targetFlags=FOREGROUND", "targetFlags=FOREGROUND | FOREGROUND"),
            ("foreign-extra-field", "mDeviceStates=", "inputConfig=SPY, mDeviceStates="),
            ("invalid-token", "forwardingWindowToken=(nil)", "forwardingWindowToken=garbage"),
            ("device-overflow", "DeviceId(17)", "DeviceId(2147483648)"),
            ("missing-colon", "DeviceId(17):", "DeviceId(17)"),
            ("empty-pointers", "touchingPointers=[Pointer(id=0, FINGER)]", "touchingPointers=[]"),
            ("pointer-overflow", "Pointer(id=0, FINGER)", "Pointer(id=32, FINGER)"),
            ("duplicate-pointer", "Pointer(id=0, FINGER)", "Pointer(id=0, FINGER), Pointer(id=0, FINGER)"),
            ("missing-state", "          DeviceId(17):[touchingPointers=[Pointer(id=0, FINGER)], downTimeInTarget=1000000000, hoveringPointers=[], pilferingPointerIds=<none>]\n", ""),
            ("extra-row", "  CursorStatesByDisplay:", "        1: name='extra'\n  CursorStatesByDisplay:")]
        for name, old, new in changes:
            with self.subTest(name=name), self.assertRaises(ValueError): dispatcher_windows(raw.replace(old, new))
        state = next(line for line in raw.splitlines() if "DeviceId(17)" in line)
        with self.assertRaises(ValueError): dispatcher_windows(raw.replace(state, state + "\n" + state))
        before, after = raw.split("  CursorStatesByDisplay:", 1)
        misplaced = self.raw().replace("  Connections:", self.touching() + "  Connections:")
        with self.assertRaises(ValueError): dispatcher_windows(misplaced)
        with self.assertRaises(ValueError): dispatcher_windows(before.replace(self.touching(), "") + "  CursorStatesByDisplay:" + after + self.touching())

    def test_history_or_later_ims_touch_rows_cannot_supply_missing_current_roots(self):
        live = self.raw().replace("  TouchStatesByDisplay: <no displays touched>\n", "")
        for extra in (IMS + self.touching(), self.touched_dump().replace(
                "Input Dispatcher State:", "Input Dispatcher State at time of last ANR:")):
            with self.subTest(extra=extra), self.assertRaises(ValueError): dispatcher_windows(live + extra)
        self.assertEqual(1, self.check(self.raw() + IMS + self.touching())["active"])

    def test_actual_failed_systemui26a_keeps_stock_spy_rejected(self):
        path = Path("/var/tmp/wonad-native-runtime26.nrj63mts/runners/android/out/native-systemui-death-26a/death-inactive-0-input.txt")
        if not path.is_file(): self.skipTest("Original failed26a diagnostic unavailable")
        raw = path.read_text()
        self.assertEqual(dict(active=1, hidden=0, token=int("7ce08a992b70", 16), layers=[190], mode="parked"), self.check(raw))
        with self.assertRaisesRegex(ValueError, "Parked display retains"):
            shell_input_handles(raw, [2], 10180, parked=True)
        # In-memory synthetic negative control ONLY; the sealed dump is never
        # edited. Keep genuine later IMS inventory while independently removing
        # the actual Dispatcher spy, proving the two records are distinct.
        lines = raw.splitlines()
        offending = [line for line in lines if re.match(r"      \d+: name=\[Gesture Monitor\] edge-swipe,", line)
            and "displayId=2," in line and "ownerPid=4857," in line]
        self.assertEqual(1, len(offending))
        control = "\n".join(line for line in lines if line not in offending)
        # Reindex only that synthetic display's remaining row ordinals.
        current, index = False, 0
        control_lines = []
        for line in control.splitlines():
            if line == "  Display: 2": current, index = True, 0
            elif re.match(r"^  \S", line): current = False
            if current and re.match(r"      \d+: name=", line):
                line = re.sub(r"^      \d+:", f"      {index}:", line); index += 1
            control_lines.append(line)
        control = "\n".join(control_lines)
        self.assertIn("InputChannel token=android.os.BinderProxy@e0c72a7, displayId=2", control)
        self.assertEqual(1, self.check(control)["active"])
        self.assertEqual(0, shell_input_handles(control, [2], 10180, parked=True)[2]["spies"])


if __name__ == "__main__": unittest.main()
