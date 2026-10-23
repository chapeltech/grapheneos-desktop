import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import systemui_death_smoke as death


class SystemUiDeathTest(unittest.TestCase):
    def test_crash_is_exact_process_and_injected_reason(self):
        log = "Process: com.android.systemui, PID: 1234\nandroid.app.RemoteServiceException$CrashedByAdbException: shell-induced crash\n"
        self.assertEqual(death.crash_evidence(log, "1234")["pid"], 1234)
        for changed in (log.replace("1234", "12345"), log.replace("systemui", "settings"),
                        log.replace("shell-induced crash", "other crash")):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                death.crash_evidence(changed, "1234")

    def test_scoped_crash_uses_explicit_package_and_user(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.guard = Mock()
        emulator.systemui_pid = Mock(return_value="1234")
        emulator.shell = Mock(return_value="")
        emulator.crash_systemui("1234")
        emulator.guard.assert_called_once()
        emulator.shell.assert_called_once_with("am", "crash", "--user", 0, "com.android.systemui")

    def test_changed_process_prevents_crash(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.guard = Mock()
        emulator.systemui_pid = Mock(return_value="5678")
        emulator.shell = Mock()
        with self.assertRaises(ValueError):
            emulator.crash_systemui("1234")
        emulator.shell.assert_not_called()

    def test_failed_isolation_prevents_crash(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.guard = Mock(side_effect=ValueError("not isolated"))
        emulator.systemui_pid = Mock()
        emulator.shell = Mock()
        with self.assertRaises(ValueError):
            emulator.crash_systemui("1234")
        emulator.systemui_pid.assert_not_called()
        emulator.shell.assert_not_called()

    def test_crash_command_refusal_is_not_success(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.guard = Mock()
        emulator.systemui_pid = Mock(return_value="1234")
        emulator.shell = Mock(return_value="Shell does not have permission to crash packages for user 0")
        with self.assertRaises(ValueError):
            emulator.crash_systemui("1234")

    def test_activity_recreation_or_task_replacement_fails(self):
        identities = {"one": 17, "two": 18}
        original = {c: dict(task=t, display=2, instance=c) for c, t in identities.items()}
        death.same_lifetimes(original, original, identities, 2)
        for key, value in (("task", 19), ("display", 0), ("instance", "new-object")):
            changed = copy.deepcopy(original)
            changed["one"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                death.same_lifetimes(changed, original, identities, 2)

    def test_only_normal_apks_are_installed_in_separate_container(self):
        self.assertEqual(death.DeathEmulator.label, "org.wonad.isolated-systemui-death-test")
        self.assertEqual(set(death.DeathEmulator.allowed_packages), {death.APP, death.PACKAGE})
        self.assertTrue(issubclass(death.DeathEmulator, death.FreshEmulator))

    def test_pid_query_is_bounded_and_unique(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.shell = Mock(return_value="1234")
        self.assertEqual(emulator.pid(death.APP), "1234")
        with self.assertRaises(ValueError):
            emulator.pid("unrelated.app")
        emulator.shell.return_value = "1234 5678"
        with self.assertRaises(ValueError):
            emulator.pid("system_server")

    def test_native_recovery_checks_client_inactivity_before_observing_windows(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.owner = Mock(evidence={})
        paused = Mock(side_effect=ValueError("client reconnected"))
        emulator.observe = Mock()
        with self.assertRaisesRegex(ValueError, "client reconnected"):
            emulator.native_recovery("42", "100", "1234", {}, {}, {}, 2, {}, paused)
        paused.assert_called_once_with()
        emulator.observe.assert_not_called()

    def test_native_recovery_never_queries_or_commands_the_policy(self):
        emulator = object.__new__(death.DeathEmulator)
        emulator.owner = Mock(evidence={})
        paused = Mock()
        emulator.pid = Mock(return_value="100")
        identities = dict(zip(death.COMPONENTS, (17, 18)))
        records = {c: dict(task=t, display=2, instance=c, left=0, top=0,
                          right=100, bottom=100, key_downs=0) for c, t in identities.items()}
        emulator.observe = Mock(return_value=(records, {}))
        emulator.shell = Mock(return_value="1235 com.android.systemui\n")
        emulator.systemui_pid = Mock(return_value="1235")
        emulator.wait_for_transitions = Mock()
        emulator.mouse_focus = Mock(return_value=(records, 1))
        emulator.until = Mock(return_value=(records, {}))
        emulator.service = Mock(side_effect=AssertionError("policy must not be queried"))
        emulator.chord = Mock(side_effect=AssertionError("no policy commands during native recovery"))
        with patch.object(death, "native_identities", return_value={}), \
                patch.object(death, "primary_systemui_process", return_value="1235"), \
                patch.object(death, "task_visibility", return_value={17: True, 18: True}):
            self.assertEqual(emulator.native_recovery("42", "100", "1234", records, identities,
                {}, 2, {c: [0, 0, 100, 100] for c in identities}, paused), "1235")
        emulator.service.assert_not_called()
        emulator.chord.assert_not_called()
        self.assertEqual(paused.call_count, 5)
        self.assertEqual(set(emulator.owner.evidence["native_input"]), set(identities))


if __name__ == "__main__":
    unittest.main()
