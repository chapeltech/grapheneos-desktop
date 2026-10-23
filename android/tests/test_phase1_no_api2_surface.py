"""Fail closed if the deleted draft-v2 desktop surface returns.

Workspace state in ``android/desktop`` and ``policy`` is deliberately owned by
the ordinary Wonad APK.  This guard covers the SDK, privileged adapter and
client negotiation boundary instead of banning that private policy.
"""

from pathlib import Path
import re
import unittest


ANDROID = Path(__file__).resolve().parents[1]
SDK = ANDROID / "desktop-sdk/src/main"
BROKER = ANDROID / "os-integration/src/org/wonad/desktop/broker"
OBSOLETE_API2_PATHS = (
    ANDROID / "broker-core/src/main/kotlin/org/wonad/desktop/broker/TaskContinuity.kt",
    ANDROID / "tests/test_task_continuity_failure_compiled.py",
)
CLIENTS = (
    ANDROID / "desktop/src/main",
    ANDROID / "conformance/src/main",
    ANDROID / "session-security/src/main",
    ANDROID / "native-prerequisites/src/main",
    ANDROID / "native-task-reuse/src/main",
    ANDROID / "transition-fault/src/main",
    ANDROID / "probe/src/main",
)

DELETED_NAMES = (
    "DesktopLayout",
    "DesktopWorkspace",
    "DesktopWindow",
    "DesktopMonitor",
    "DesktopCommand",
    "openNativeSession",
    "IDesktopNativeSession",
    "IDesktopNativeCallback",
    "NativeDesktopFrame",
    "NativeDesktopSnapshot",
    "NativeDisplay",
    "NativeTask",
    "NativePlacement",
    "NativeShellRegion",
    "NativeLaunchPage",
    "NATIVE_API_VERSION",
    "CAP_NATIVE_FRAME",
    "CAP_NATIVE_SHELL",
    "CAP_NATIVE_SIGNED_PLACEMENT",
    "MAX_NATIVE_COORDINATE",
    "MAX_NATIVE_DISPLAYS",
)


def source_files(root: Path):
    return sorted(path for path in root.rglob("*")
                  if path.is_file() and path.suffix in {".aidl", ".java", ".kt", ".xml"})


class Phase1NoApi2Surface(unittest.TestCase):
    def test_obsolete_api2_task_continuity_surface_is_absent(self):
        for path in OBSOLETE_API2_PATHS:
            self.assertFalse(path.exists() or path.is_symlink(),
                             f"deleted API2-only surface returned: {path.relative_to(ANDROID)}")

    def test_deleted_types_methods_and_client_fallback_are_absent(self):
        roots = (SDK, BROKER, *CLIENTS)
        for path in (path for root in roots for path in source_files(root)):
            text = path.read_text()
            for name in DELETED_NAMES:
                self.assertNotRegex(text, r"\b" + re.escape(name) + r"\b",
                                    f"{name} survived in {path.relative_to(ANDROID)}")

    def test_sdk_contains_only_the_frozen_v3_aidl_shape(self):
        aidl = SDK / "aidl/org/wonad/desktop/api"
        self.assertEqual({
            "DesktopDisplay.aidl", "DesktopFrame.aidl", "DesktopLaunchEntry.aidl",
            "DesktopLaunchPage.aidl", "DesktopPlacement.aidl", "DesktopRect.aidl",
            "DesktopShellRegion.aidl", "DesktopSnapshot.aidl", "DesktopTask.aidl",
            "IDesktopBroker.aidl", "IDesktopCallback.aidl", "IDesktopSession.aidl",
        }, {path.name for path in aidl.glob("*.aidl")})
        broker = (aidl / "IDesktopBroker.aidl").read_text()
        self.assertEqual(["getApiVersion", "getCapabilities", "openSession"],
                         re.findall(r"\b(?:int|long|IDesktopSession)\s+(\w+)\(", broker))
        session = (aidl / "IDesktopSession.aidl").read_text()
        self.assertEqual(13, len(re.findall(
            r"(?:oneway void|@nullable DesktopLaunchPage)\s+\w+\(", session)))

    def test_os_rejects_every_non_v3_open_and_has_no_workspace_wire_field(self):
        controller = (BROKER / "NativeDesktopController.kt").read_text()
        opening = controller.split("fun open(", 1)[1].split("private fun wm()", 1)[0]
        self.assertIn("require(version == DesktopProtocol.API_VERSION)", opening)
        self.assertNotIn("version == 2", opening)
        declarations = []
        for path in (SDK / "aidl/org/wonad/desktop/api").glob("*.aidl"):
            uncommented = re.sub(r"/\*.*?\*/|//[^\n]*", "", path.read_text(), flags=re.S)
            declarations.extend(re.findall(r"[^{};]+;", uncommented))
        self.assertFalse(any(re.search(r"\bworkspace\b", row, re.I) for row in declarations))

    def test_picker_and_launcher_models_have_no_workspace_compatibility_overload(self):
        picker = (BROKER / "WonadPickerUi.kt").read_text()
        functions = re.findall(r"^\s*(?:private\s+)?fun\s+(\w+)\(", picker, re.M)
        self.assertNotIn("show", functions)
        self.assertIn("showNativeTransfer", functions)
        catalog = (ANDROID / "desktop/src/main/kotlin/org/wonad/desktop/LauncherCatalog.kt").read_text()
        model = catalog.split("internal data class LauncherCatalog", 1)[1].split(") {", 1)[0]
        self.assertNotRegex(model, r"\bworkspace\b")
        self.assertIn("return LauncherCatalog(generation, id, display, expiresAt", catalog)

    def test_workspace_policy_remains_explicitly_apk_private(self):
        codec = (ANDROID / "desktop/src/main/kotlin/org/wonad/desktop/NativeDesktopPolicyCodec.kt").read_text()
        policy = (ANDROID.parent / "policy/src/Wonad/Policy/NativeDesktop.hs").read_text()
        self.assertIn("Workspace/floating metadata never enters native", codec)
        self.assertIn("ownWorkspaces", policy)
        self.assertIn("decisionWorkspaces", policy)


if __name__ == "__main__":
    unittest.main()
