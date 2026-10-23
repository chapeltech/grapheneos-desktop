"""The API3 OS port must not retain API2 Shell disconnect bookkeeping."""

from pathlib import Path
import importlib.util
import unittest


ANDROID = Path(__file__).resolve().parents[1]
STAGE = ANDROID / "platform/stage-os.py"
PATCHES = ANDROID / "platform/patches"
CONTROLLER = ANDROID / "os-integration/src/org/wonad/desktop/broker/WonadController.kt"
PORT = ANDROID / "platform/PORT-2026100600.md"

OBSOLETE = {
    "wonad-redock.patch",
    "wonad-multi-display.patch",
    "wonad-disconnect-bookkeeping.patch",
    "wonad-reconnect.patch",
    "wonad-reconnect-tests.patch",
    "wonad-reconnect-settling.patch",
    "wonad-disconnected-desk-roots.patch",
}
HOOKS = {
    "prepareDisplayDisconnect",
    "disconnectDestination",
    "retainsTaskForReconnect",
    "finishDisplayDisconnect",
}


def staged_patches():
    spec = importlib.util.spec_from_file_location("phase1_stage", STAGE)
    stage = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stage)
    return list(stage.stage_contract.FRAMEWORK_PATCH_NAMES)


def targets(names):
    return {line.removeprefix("+++ b/") for name in names
            for line in (PATCHES / name).read_text().splitlines()
            if line.startswith("+++ b/")}


class Phase1NoApi2ShellGlue(unittest.TestCase):
    def test_obsolete_patch_chain_is_absent_as_one_atomic_change(self):
        names = staged_patches()
        self.assertEqual(41, len(names))
        self.assertEqual("wonad-authoritative-focus-framework.patch", names[-1])
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(OBSOLETE.isdisjoint(names))
        self.assertTrue(all(not (PATCHES / name).exists() for name in OBSOLETE))
        self.assertTrue(all((PATCHES / name).is_file() for name in names))
        self.assertEqual(53, len(targets(names[:-1])))
        self.assertEqual(60, len(targets(names)))
        # The API3 WMS-owned removal/containment implementation remains staged.
        self.assertIn("wonad-native-recovery.patch", names)
        self.assertIn("wonad-native-frame.patch", names)
        self.assertIn("wonad-native-protected-ui.patch", names)

    def test_no_noop_controller_or_shell_test_compatibility_surface_remains(self):
        controller = CONTROLLER.read_text()
        for hook in HOOKS:
            self.assertNotIn(hook, controller)
        self.assertNotIn("WindowContainerTransaction", controller)
        self.assertFalse((ANDROID / "tests/test_legacy_disconnect_recovery_compiled.py").exists())
        framework = (ANDROID / "tools/framework_regression.py").read_text()
        self.assertNotIn("SHELL_CASES", framework)
        self.assertNotIn("shell-reconnect", framework)
        for patch in OBSOLETE:
            self.assertNotIn(patch, framework)

    def test_port_inventory_describes_the_reduced_reviewed_stack(self):
        port = PORT.read_text()
        self.assertIn("All 41 ordered `frameworks/base` patches", port)
        self.assertIn("produce 60 owned target files", port)
        self.assertIn("API3's WMS-owned physical-removal and fail-black paths", port)


if __name__ == "__main__":
    unittest.main()
