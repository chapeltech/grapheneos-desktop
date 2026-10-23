"""Adversarial tests for the separate fresh-guest Phase-1 conformance path."""
from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ANDROID = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


builder = module("phase1_conformance_candidate_test_builder",
                 ANDROID / "container/build-phase1-conformance-candidate.py")
common = module("phase1_conformance_common_test", ANDROID / "tools/phase1_conformance_common.py")
acceptance = module("phase1_conformance_acceptance_test", ANDROID / "tools/phase1_conformance_acceptance.py")
guest = module("phase1_conformance_guest_launch_test", ANDROID / "tools/phase1_conformance_guest.py")

IMAGE = "sha256:" + "1" * 64
WONAD_SIGNER = builder.packet_tool.WONAD_CERT
FIXTURE_SIGNER = "b" * 64
PLATFORM_SIGNER = "c" * 64
FINGERPRINT = "Android/sdk_phone64_x86_64/emu64x:37/TEST/wonad.20261010:userdebug/test-keys"
APP = acceptance.APP
FIXTURE = acceptance.FIXTURE
FAULT = acceptance.FAULT
HOME_COMPONENT = "com.android.launcher3/.uioverrides.QuickstepLauncher"
HOME_FULL_COMPONENT = ("com.android.launcher3/"
                       "com.android.launcher3.uioverrides.QuickstepLauncher")


def phone_home_activities(component=HOME_COMPONENT, full_component=HOME_FULL_COMPONENT,
                          *, display=0, activity_type="home", state="RESUMED"):
    return (
        "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
        "Display #0 (activities from top to bottom):\n"
        f"  * Task{{abc #1 type={activity_type} U=0 visible=true visibleRequested=true mode=fullscreen}}\n"
        f"    topResumedActivity=ActivityRecord{{def u0 {component} t1}}\n"
        f"    * Hist  #0: ActivityRecord{{def u0 {component} t1}}\n"
        f"      mActivityComponent={component}\n"
        f"      state={state} finishing=false\n"
        f"      mActivityType={activity_type}\n"
        "      mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true\n"
        "      nowVisible=true lastVisibleTime=-1s234ms\n"
        "Display #3 (activities from top to bottom):\n"
        f"  ResumedActivity: ActivityRecord{{def u0 {component} t1}}\n"
        f"  Display: mDisplayId={display} (organized)\n"
        f"    mCurrentFocus=Window{{123abc u0 {full_component}}}\n"
        f"    mFocusedApp=ActivityRecord{{def u0 {component} t1}}\n"
        "  Display: mDisplayId=3 (organized)\n")


def phone_home_windows(full_component=HOME_FULL_COMPONENT, *, display=0, focused=0,
                       visible=True):
    shown = "true" if visible else "false"
    return (
        "WINDOW MANAGER WINDOWS (dumpsys window windows)\n"
        f"  Window #0 Window{{123abc u0 {full_component}}}:\n"
        f"    mDisplayId={display} mSession=Session{{1}}\n"
        f"    mHasSurface={shown} isReadyForDisplay()={shown}\n"
        f"    isOnScreen={shown}\n"
        f"    isVisible={shown}\n"
        f"  mTopFocusedDisplayId={focused}\n")


def stock_shaped_phone_home_activities():
    """Faithful bounded excerpt of the pinned ActivityRecord/Display dump grammar."""
    return """ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  * Task{8a1f935 #1 type=home U=0 visible=true visibleRequested=true mode=fullscreen translucent=false sz=1}
    fullscreenRequestAllowMode=NONE
    isSleeping=false
    topResumedActivity=ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}
    * Hist  #0: ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}
      packageName=com.android.launcher3 processName=com.android.launcher3
      launchedFromUid=0 launchedFromPackage=null launchedFromFeature=null userId=0
      app=ProcessRecord{8683d29 1438:com.android.launcher3/u0a152}
      Intent { act=android.intent.action.MAIN cat=[android.intent.category.HOME] flg=0x10000100 cmp=com.android.launcher3/.uioverrides.QuickstepLauncher }
      rootOfTask=true task=Task{7a3bee2 #9 type=home I=com.android.launcher3/.uioverrides.QuickstepLauncher}
      taskAffinity=null
      mActivityComponent=com.android.launcher3/.uioverrides.QuickstepLauncher
      baseDir=/system/priv-app/Launcher3QuickStep/Launcher3QuickStep.apk
      dataDir=/data/user/0/com.android.launcher3
      stateNotNeeded=true componentSpecified=false mActivityType=home
      compat={420dpi} theme=0x7f13014f
      launchFailed=false launchCount=1 lastLaunchTime=-2s105ms
      mHaveState=true mIcicle=Bundle[mParcelledData.dataSize=900]
      state=RESUMED finishing=false
      keysPaused=false inHistory=true idle=true
      occludesParent=false mNoDisplay=false immersive=false launchMode=2
      mActivityType=home
      windows=[Window{c02af8a u0 com.android.launcher3/com.android.launcher3.uioverrides.QuickstepLauncher}]
      windowType=1
      mVisibleRequested=true mVisible=true mClientVisible=true reportedDrawn=true reportedVisible=true
      mNumInterestingWindows=1 mNumDrawnWindows=1 allDrawn=true)
      startingData=null firstWindowDrawn=true
      nowVisible=true lastVisibleTime=-1s482ms
Display #3 (activities from top to bottom):
  * Task{69fad5b #19 type=home U=0 visible=true visibleRequested=true mode=fullscreen translucent=false sz=1}

  Resumed activities in task display areas (from top to bottom):
    Resumed: ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}

  ResumedActivity: ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}

ActivityTaskSupervisor state:
  topDisplayFocusedRootTask=Task{8a1f935 #1 type=home}
  Display: mDisplayId=0 (organized)
    init=1080x2400 420dpi mMinSizeOfResizeableTaskDp=220 cur=1080x2400 app=1080x2400
  mSleeping=false mAllSleepTokens=[]
  mLayoutSeq=95
  mImeWindow=null
  mImeLayeringTarget=null
  mCurrentFocus=Window{c02af8a u0 com.android.launcher3/com.android.launcher3.uioverrides.QuickstepLauncher}
  mFocusedApp=ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}
  mFixedRotationLaunchingApp=null

  Display: mDisplayId=3 (organized)
    init=1920x1080 240dpi mMinSizeOfResizeableTaskDp=220 cur=1920x1080 app=1920x1080
"""


def stock_shaped_phone_home_windows():
    """Faithful bounded excerpt of the pinned WindowState dump grammar."""
    return """WINDOW MANAGER WINDOWS (dumpsys window windows)
  Window #8 Window{c02af8a u0 com.android.launcher3/com.android.launcher3.uioverrides.QuickstepLauncher}:
    mDisplayId=0 taskId=9 mSession=Session{97d9625 1438:u0a10152} mClient=android.os.BinderProxy@76495f5
    mOwnerUid=10152 showForAllUsers=false package=com.android.launcher3 appop=NONE
    mAttrs={(0,0)(fillxfill) sim={adjust=nothing} ty=BASE_APPLICATION fmt=TRANSPARENT
      fl=LAYOUT_IN_SCREEN LAYOUT_INSET_DECOR SHOW_WALLPAPER HARDWARE_ACCELERATED}
    Requested w=1080 h=2400 mLayoutSeq=64
    mBaseLayer=21000 mSubLayer=0    mToken=ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}
    mActivityRecord=ActivityRecord{228420525 u0 com.android.launcher3/.uioverrides.QuickstepLauncher t9}
    drawnStateEvaluated=true    mightAffectAllDrawn=true
    mViewVisibility=0x0 mHaveFrame=true mObscured=false
    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false
    Frames: parent=[0,0][1080,2400] display=[0,0][1080,2400] frame=[0,0][1080,2400]
    WindowStateAnimator{644ecac com.android.launcher3/com.android.launcher3.uioverrides.QuickstepLauncher}:
      mSurface=Surface(name=VRI-QuickstepLauncher#110)/@0xefc8891
      Surface: shown=true      mDrawState=HAS_DRAWN       mLastHidden=false
    isOnScreen=true
    isVisible=true
    keepClearAreas: restricted=[], unrestricted=[]
  Window #9 Window{d0011d2 u0 com.android.systemui.wallpapers.ImageWallpaper}:
    mDisplayId=0 mSession=Session{5d64ab3 1150:u0a10148}
    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false
    isOnScreen=true
    isVisible=true
  #0 Window{c02af8a u0 com.android.launcher3/com.android.launcher3.uioverrides.QuickstepLauncher}:
    mDisplayId=0 taskId=9 mSession=Session{97d9625 1438:u0a10152}
    mHasSurface=true isReadyForDisplay()=true mWindowRemovalAllowed=false
    isOnScreen=true
    isVisible=true
  mTopFocusedDisplayId=0
"""


def artifact(role, data):
    expected = {
        "wonad": ("org.wonad.desktop", 12, "phase1-neutral-v3-12", WONAD_SIGNER, False, False, []),
        "conformance": ("org.wonad.desktop", 1, "3.0-phase1-conformance", WONAD_SIGNER, False, False,
                        ["org.wonad.desktop"]),
        "fixture": ("org.wonad.fixture", 1, "0.1", FIXTURE_SIGNER, True, False, []),
        "fault": ("org.wonad.desktop.transitionfault", 1, "0.1-test-only", PLATFORM_SIGNER, False, True,
                  ["com.android.systemui"]),
        "security": ("org.wonad.desktop.test", 1, "0.1-test-only", WONAD_SIGNER, False, True,
                     ["org.wonad.desktop"]),
    }[role]
    package, version, version_name, signer, debuggable, test_only, targets = expected
    return {"sha256": common.sha256(data), "bytes": data.stat().st_size, "package": package,
        "version_code": version, "version_name": version_name, "certificate_der_sha256": signer,
        "signers": 1, "schemes": {"3": True}, "debuggable": debuggable, "test_only": test_only,
        "instrumentation_targets": targets, "shared_uid": False, "privileged_manifest": False}


def terminal(run="d" * 32, display=3):
    return {"schema": 1, "run": run, "mode": "full", "state": "passed", "phase": "complete",
        "started_elapsed_ms": 100, "updated_elapsed_ms": 200, "api_version": 3,
        "capabilities": common.REQUIRED_CAPABILITIES, "generation": 9, "display_ids": [display],
        "heartbeat_count": 2, "operations": list(common.OPERATIONS),
        "callbacks": {name: 1 for name in common.CALLBACKS}, "facades": list(common.FACADES),
        "failure": None}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="phase1-fresh-conformance-test-")
        self.root = Path(self.temporary.name)
        self.product = self.root / "product"; self.product.mkdir()
        self.base_files = {}
        import build
        from modem_packaging_fixture import install
        pins = install(self, self.product, build)
        self.base_files.update({"/product/" + name: checksum for name, checksum in pins.items()})
        self.base_files["/opt/wonad/modem_assets.py"] = common.sha256(builder.ROOT / "android/demo/modem_assets.py")
        for name in builder.IMAGE_FILES:
            path = self.product / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("product:" + name).encode())
            self.base_files["/product/" + name] = common.sha256(path)
        (self.product / "build_fingerprint-sdk_phone64_x86_64.txt").write_text(FINGERPRINT + "\n")
        self.base_files["/product/build_fingerprint-sdk_phone64_x86_64.txt"] = common.sha256(
            self.product / "build_fingerprint-sdk_phone64_x86_64.txt")
        self.os_artifacts = {}
        for role, relative in builder.OS_PATHS.items():
            path = self.product / relative; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("os:" + role).encode())
            self.os_artifacts[role] = common.sha256(path)
        self.packet = self.root / "packet"; self.packet.mkdir()
        role_files = {"wonad": "wonad.apk", "conformance": "conformance.apk",
                      "fixture": "fixture.apk", "fault": "fault.apk", "security": "security.apk"}
        self.artifacts = {}
        for role, name in role_files.items():
            path = self.packet / name; path.write_bytes(("apk:" + role).encode())
            self.artifacts[role] = artifact(role, path)
        update = self.packet / builder.packet_tool.CONFORMANCE_UPDATE_DIRECTORY
        update.mkdir()
        original = update / builder.packet_tool.CONFORMANCE_UPDATE_FILES["original"]
        candidate = update / builder.packet_tool.CONFORMANCE_UPDATE_FILES["candidate"]
        unsigned = update / builder.packet_tool.CONFORMANCE_UPDATE_FILES["unsigned"]
        original.write_bytes((self.packet / "conformance.apk").read_bytes())
        candidate.write_bytes(b"apk:conformance-v2")
        unsigned.write_bytes(b"apk:conformance-v2-unsigned")
        normalized, payload = "d" * 64, "e" * 64
        def update_member(path, version):
            return {"file": common.file_ref(path), "package": "org.wonad.desktop",
                "version_code": version, "version_name": "3.0-phase1-conformance",
                "certificate_der_sha256": WONAD_SIGNER,
                "normalized_manifest_sha256": normalized,
                "non_manifest_payload_sha256": payload}
        v1, v2 = update_member(original, 1), update_member(candidate, 2)
        version_only = {"package": "org.wonad.desktop",
            "version_name": "3.0-phase1-conformance", "certificate_der_sha256": WONAD_SIGNER,
            "original_version_code": 1, "candidate_version_code": 2,
            "normalized_manifest_sha256": normalized, "non_manifest_payload_sha256": payload,
            "permissions_binding": "exact_binary_manifest_equality_except_root_version_code"}
        remote = "/tmp/phase1-client-signing.Ab12Cd34"
        argv = [
            [builder.packet_tool.OPENSSL, "pkcs8", "-topk8", "-nocrypt", "-in", remote + "/existing.pem",
             "-outform", "DER", "-out", remote + "/existing.pk8"],
            [builder.packet_tool.ZIPALIGN, "-P", "16", "-f", "4", remote + "/unsigned.apk",
             remote + "/aligned.apk"],
            [builder.packet_tool.APKSIGNER, "sign", "--key", remote + "/existing.pk8", "--cert",
             remote + "/existing.x509.pem", "--v1-signing-enabled", "true",
             "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
             "--v4-signing-enabled", "false", "--out", remote + "/candidate.apk",
             remote + "/aligned.apk"],
            [builder.packet_tool.ZIPALIGN, "-c", "-P", "16", "4", remote + "/candidate.apk"],
        ]
        preparation = {"schema": 1, "api": 3,
            "kind": "phase1_conformance_version_only_preparation_v1",
            "status": "prepared_not_runtime_qualified", "development_only": True,
            "runtime_qualified": False, "guests_started": False,
            "tools": {"container_id": "7" * 64, "image_id": "sha256:" + "8" * 64,
                      "label_token": "9" * 32},
            "source": common.file_ref(self.packet / "conformance.apk"),
            "artifacts": {"v1": v1, "v2": v2}, "version_only": version_only,
            "private_data_canary": {"runner": builder.packet_tool.UPDATE_CANARY_RUNNER,
                "source_sha256": builder.packet_tool.UPDATE_CANARY_SHA256},
            "commands": [{"argv": row, "stdout": "",
                          "stdout_sha256": builder.packet_tool.sha_bytes(b""),
                          "stdout_bytes": 0} for row in argv],
            "files": {path.name: common.file_ref(path) for path in (original, candidate, unsigned)}}
        preparation_path = update / builder.packet_tool.CONFORMANCE_UPDATE_RECEIPT
        preparation_path.write_bytes(common.canonical(preparation))
        conformance_update = {"receipt": common.file_ref(preparation_path), "v1": v1, "v2": v2,
            "version_only": version_only, "private_data_canary": preparation["private_data_canary"],
            "temporary_private_key_removed": True}
        compile_receipt = self.packet / builder.packet_tool.SECURITY_BUILD_RECEIPT
        source_freeze = self.packet / builder.packet_tool.SECURITY_SOURCE_FREEZE
        compile_receipt.write_text("security compile receipt\n")
        source_freeze.write_text("security source freeze\n")
        security_compile = {"receipt": common.file_ref(compile_receipt),
            "source_freeze": common.file_ref(source_freeze),
            "canary_source_sha256": builder.packet_tool.UPDATE_CANARY_SHA256,
            "compiled_files": 2, "tests": 1}
        packet_tools_image = "sha256:" + "5" * 64
        packet_tool_hashes = {
            builder.APKSIGNER: "6" * 64,
            builder.APKSIGNER_JAR: "7" * 64,
        }
        self.receipt = {"schema": 2,
            "kind": "phase1_source_matched_x86_development_client_packet_v1",
            "status": "compile_qualified_development_packet_not_runtime_qualified",
            "development_only": True, "runtime_qualified": False,
            "tools": {"image_id": packet_tools_image, "tools": packet_tool_hashes},
            "signers": {"systemui_platform_development": {
                "certificate_der_sha256": PLATFORM_SIGNER}},
            "artifacts": self.artifacts, "conformance_version_update": conformance_update,
            "security_compile": security_compile}
        (self.packet / "receipt.json").write_bytes(common.canonical(self.receipt))
        self.receipt_sha = common.sha256(self.packet / "receipt.json")
        self.base_files["/opt/wonad/wonad.apk"] = self.artifacts["wonad"]["sha256"]
        self.base_files["/opt/wonad/session.py"] = "e" * 64
        self.base_files["/opt/wonad/entrypoint.py"] = "f" * 64
        evidence_rows = {}
        for index, (role, filename) in enumerate(builder.native.PHASE1_EVIDENCE_NAMES.items(), 1):
            checksum = str(index) * 64
            bundle_path = "/opt/wonad/build-evidence/" + filename
            self.base_files[bundle_path] = checksum
            evidence_rows[role] = {"bundle_path": bundle_path, "expected_sha256": checksum,
                                   "file": {"sha256": checksum, "size": index}}
        evidence_rows["comparison"].update(schema=1, kind="x86-comparison",
                                            result="passed_exact_clean_baseline_custom_delta")
        evidence_rows["baseline_receipt"].update(role="baseline", fingerprint=FINGERPRINT,
                                                  container_id="1" * 64)
        evidence_rows["custom_receipt"].update(role="custom", fingerprint=FINGERPRINT,
                                                container_id="2" * 64)
        packet_row = evidence_rows.pop("client_packet_receipt")
        packet_row.update(schema=2,
            kind="phase1_source_matched_x86_development_client_packet_v1",
            status="compile_qualified_development_packet_not_runtime_qualified",
            development_only=True, runtime_qualified=False,
            packet_directory=str(self.packet),
            wonad_apk={"bundle_path": "/opt/wonad/wonad.apk",
                "sha256": self.artifacts["wonad"]["sha256"],
                "size": self.artifacts["wonad"]["bytes"],
                "certificate_der_sha256": WONAD_SIGNER},
            staged_signer_der_sha256=WONAD_SIGNER)
        signer_rows = {}
        for role, apk_path in (
                ("systemui", self.product / builder.OS_PATHS["com.android.systemui"]),
                ("fault", self.packet / "fault.apk")):
            apk_sha256 = common.sha256(apk_path)
            transcript = (
                packet_tool_hashes[builder.APKSIGNER] + "  " + builder.APKSIGNER + "\n" +
                packet_tool_hashes[builder.APKSIGNER_JAR] + "  " + builder.APKSIGNER_JAR + "\n" +
                apk_sha256 + "  /tmp/input.apk\n" +
                "Verified using v3 scheme (APK Signature Scheme v3): true\n" +
                "Signer #1 certificate SHA-256 digest: " + PLATFORM_SIGNER + "\n")
            transcript_path = ("/opt/wonad/build-evidence/" +
                               builder.native.PHASE1_SIGNER_TRANSCRIPTS[role])
            transcript_sha256 = builder.packet_tool.sha_bytes(transcript.encode())
            self.base_files[transcript_path] = transcript_sha256
            signer_rows[role] = {
                "apk": {"sha256": apk_sha256, "size": apk_path.stat().st_size},
                "transcript": {"bundle_path": transcript_path,
                               "sha256": transcript_sha256,
                               "size": len(transcript.encode())},
            }
        packet_row["systemui_fault_signer"] = {
            "schema": 1,
            "scope": "authenticated-packet-tools-exact-systemui-fault-signer-match",
            "runtime_qualified": False,
            "verifier": {
                "image_id": packet_tools_image,
                "apksigner": {"path": builder.APKSIGNER,
                              "sha256": packet_tool_hashes[builder.APKSIGNER]},
                "apksigner_jar": {"path": builder.APKSIGNER_JAR,
                                  "sha256": packet_tool_hashes[builder.APKSIGNER_JAR]},
            },
            "signer_der_sha256": PLATFORM_SIGNER,
            **signer_rows,
        }
        evidence_rows["client_packet"] = packet_row
        phase1_evidence = {"schema": 1,
            "scope": "authenticated-x86-clean-baseline-custom-build-evidence",
            **evidence_rows, "shared_fingerprint": FINGERPRINT, "source_pin_sha256": "4" * 64,
            "selected_custom_build": {"source": str(self.root / "source"),
                                      "out_dir": str(self.root / "out"),
                                      "product": str(self.product)}, "qualification_claimed": False}
        self.base = {"schema": 1, "architecture": "amd64", "api": 3,
            "scope": "unqualified_native_v3_exact_bundle_candidate", "fingerprint": FINGERPRINT,
            "files": self.base_files, "os_artifacts": {**self.os_artifacts,
                "org.wonad.desktop": self.artifacts["wonad"]["sha256"]},
            "native_emulator_backend_qualification": "not_passed",
            "native_multi_monitor_acceptance": "not_passed", "full_shell_acceptance": "not_passed",
            "phase1_build_evidence": phase1_evidence}

    def tearDown(self):
        self.temporary.cleanup()

    def stage(self, name="stage", receipt=None, signer=PLATFORM_SIGNER):
        output = self.root / name
        manifest = builder.stage(self.product, self.packet, receipt or self.receipt, self.receipt_sha,
                                 output, IMAGE, self.base, signer)
        return output, manifest


class CandidateTests(Fixture):
    def test_product_origin_remains_bound_even_for_byte_identical_staging_copy(self):
        products, artifacts = builder.verify_product(self.product, self.base)
        self.assertEqual(
            {name: self.base_files['/product/' + name] for name in builder.IMAGE_FILES},
            products)
        self.assertEqual(self.os_artifacts, artifacts)

        staged_copy = self.root / 'staged-product-copy'
        shutil.copytree(self.product, staged_copy)
        for original in self.product.rglob('*'):
            if original.is_file():
                self.assertEqual(original.read_bytes(),
                                 (staged_copy / original.relative_to(self.product)).read_bytes())
        with self.assertRaisesRegex(ValueError, 'not the product authenticated'):
            builder.verify_product(staged_copy, self.base)

    def test_separate_image_removes_product_and_discloses_every_unrun_gate(self):
        output, manifest = self.stage()
        self.assertNotIn("/opt/wonad/wonad.apk", manifest["files"])
        self.assertFalse(manifest["product_apk_present"])
        self.assertFalse(manifest["runtime_qualified"])
        self.assertFalse(manifest["guests_started"])
        self.assertEqual("not_run_by_this_lane",
                         manifest["systemui_fault_identity"]["runtime_fault_injection"])
        self.assertEqual("identity_verified_only_not_run",
                         manifest["planned_runtime_gates"]["platform_fault_injection"])
        self.assertEqual(self.artifacts["wonad"]["sha256"],
                         manifest["base_product_candidate"]["product_apk_sha256"])
        self.assertEqual(self.receipt_sha, manifest["packet"]["receipt_sha256"])
        for role in ("conformance", "fixture", "fault"):
            self.assertEqual((self.packet / (role + ".apk")).read_bytes(),
                             (output / "phase1-conformance" / (role + ".apk")).read_bytes())
        self.assertEqual(2, manifest["conformance_version_update"]["v2"]["version_code"])
        self.assertEqual(builder.packet_tool.UPDATE_CANARY_RUNNER,
                         manifest["update_data_canary"]["runner"])
        self.assertEqual((self.packet / "security.apk").read_bytes(),
                         (output / "phase1-conformance/update-data-canary/security.apk").read_bytes())
        common.validate_manifest(manifest)

    def test_update_pair_signer_command_and_permission_drift_fail_closed(self):
        changed = copy.deepcopy(self.receipt)
        changed["conformance_version_update"]["v2"]["certificate_der_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "version-only pair|summary"):
            self.stage("bad-update-signer", receipt=changed)
        self.assertFalse((self.root / "bad-update-signer").exists())

        preparation_path = (self.packet / builder.packet_tool.CONFORMANCE_UPDATE_DIRECTORY /
                            builder.packet_tool.CONFORMANCE_UPDATE_RECEIPT)
        preparation = common.load(preparation_path)
        preparation["commands"][2]["argv"][1] = "verify"
        preparation_path.write_bytes(common.canonical(preparation))
        changed = copy.deepcopy(self.receipt)
        changed["conformance_version_update"]["receipt"] = common.file_ref(preparation_path)
        with self.assertRaisesRegex(ValueError, "existing-key command"):
            self.stage("bad-update-command", receipt=changed)
        self.assertFalse((self.root / "bad-update-command").exists())

    def test_manifest_rejects_resealed_permission_or_canary_identity_drift(self):
        _, manifest = self.stage()
        permission = copy.deepcopy(manifest)
        permission["conformance_version_update"]["version_only"]["permissions_binding"] = "claimed"
        with self.assertRaisesRegex(ValueError, "permission/version-only"):
            common.validate_manifest(permission)
        canary = copy.deepcopy(manifest)
        canary["update_data_canary"]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "canary"):
            common.validate_manifest(canary)

    def test_product_target_and_systemui_fault_must_match_before_output_exists(self):
        changed = copy.deepcopy(self.receipt)
        changed["artifacts"]["wonad"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Base product Wonad"):
            self.stage("bad-product", receipt=changed)
        self.assertFalse((self.root / "bad-product").exists())
        with self.assertRaisesRegex(ValueError, "fault signer"):
            self.stage("bad-platform", signer="9" * 64)
        self.assertFalse((self.root / "bad-platform").exists())

    def test_custom_product_drift_is_rejected_before_staging(self):
        path = self.product / builder.IMAGE_FILES[0]
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "custom product"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_non_strict_product_candidate_cannot_enter_phase1_conformance_lane(self):
        self.base.pop("phase1_build_evidence")
        with self.assertRaisesRegex(ValueError, "strict Phase-1 build evidence"):
            self.stage()
        self.assertFalse((self.root / "stage").exists())

    def test_manifest_rejects_product_apk_and_runtime_claims(self):
        _, manifest = self.stage()
        product = copy.deepcopy(manifest); product["files"]["/opt/wonad/wonad.apk"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "product APK"):
            common.validate_manifest(product)
        claimed = copy.deepcopy(manifest); claimed["runtime_qualified"] = True
        with self.assertRaisesRegex(ValueError, "qualification disclosure"):
            common.validate_manifest(claimed)
        fault = copy.deepcopy(manifest); fault["systemui_fault_identity"]["runtime_fault_injection"] = "passed"
        with self.assertRaisesRegex(ValueError, "Fault harness"):
            common.validate_manifest(fault)

    def test_manifest_cannot_omit_one_strict_phase1_build_evidence_file(self):
        _, manifest = self.stage()
        missing = copy.deepcopy(manifest)
        missing["files"].pop(next(iter(common.PHASE1_BUILD_EVIDENCE_PATHS)))
        with self.assertRaisesRegex(ValueError, "build-evidence inventory"):
            common.validate_manifest(missing)

    def test_actual_systemui_signer_uses_packet_immutable_tools_not_mutable_container(self):
        tool_image = "sha256:" + "8" * 64
        apksigner_hash, jar_hash = "5" * 64, "6" * 64
        receipt = {"tools": {"image_id": tool_image, "tools": {
            builder.APKSIGNER: apksigner_hash, builder.APKSIGNER_JAR: jar_hash}}}
        systemui = self.product / builder.OS_PATHS["com.android.systemui"]
        output = (f"{apksigner_hash}  {builder.APKSIGNER}\n"
                  f"{jar_hash}  {builder.APKSIGNER_JAR}\n"
                  f"{common.sha256(systemui)}  /tmp/SystemUI.apk\n"
                  "Verified using v3 scheme (APK Signature Scheme v3): true\n"
                  f"Signer #1 certificate SHA-256 digest: {PLATFORM_SIGNER}\n")
        with patch.object(builder, "inspect_image", return_value={"Id": tool_image}), \
                patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)) as run:
            self.assertEqual(PLATFORM_SIGNER, builder.systemui_signer(
                self.product, receipt, common.sha256(systemui)))
        command = run.call_args.args[0]
        self.assertIn("-i", command)
        self.assertIn("--network", command); self.assertIn("none", command)
        self.assertIn("--read-only", command); self.assertIn(tool_image, command)
        changed = output.replace(apksigner_hash, "0" * 64, 1)
        with patch.object(builder, "inspect_image", return_value={"Id": tool_image}), \
                patch.object(builder.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=changed)), \
                self.assertRaisesRegex(ValueError, "verifier"):
            builder.systemui_signer(self.product, receipt, common.sha256(systemui))

    def test_systemui_signer_rejects_duplicate_sha256sum_rows(self):
        tool_image = "sha256:" + "8" * 64
        apksigner_hash, jar_hash = "5" * 64, "6" * 64
        receipt = {"tools": {"image_id": tool_image, "tools": {
            builder.APKSIGNER: apksigner_hash, builder.APKSIGNER_JAR: jar_hash}}}
        systemui = self.product / builder.OS_PATHS["com.android.systemui"]
        output = (f"{apksigner_hash}  {builder.APKSIGNER}\n"
                  f"{jar_hash}  {builder.APKSIGNER_JAR}\n"
                  f"{common.sha256(systemui)}  /tmp/SystemUI.apk\n"
                  f"{apksigner_hash}  {builder.APKSIGNER}\n"
                  "Verified using v3 scheme (APK Signature Scheme v3): true\n"
                  f"Signer #1 certificate SHA-256 digest: {PLATFORM_SIGNER}\n")
        with patch.object(builder, "inspect_image", return_value={"Id": tool_image}), \
                patch.object(builder.subprocess, "run",
                             return_value=SimpleNamespace(returncode=0, stdout=output)), \
                self.assertRaisesRegex(ValueError, "verifier"):
            builder.systemui_signer(self.product, receipt, common.sha256(systemui))

    def test_systemui_cannot_change_while_immutable_signer_is_read(self):
        tool_image = "sha256:" + "8" * 64
        apksigner_hash, jar_hash = "5" * 64, "6" * 64
        receipt = {"tools": {"image_id": tool_image, "tools": {
            builder.APKSIGNER: apksigner_hash, builder.APKSIGNER_JAR: jar_hash}}}
        systemui = self.product / builder.OS_PATHS["com.android.systemui"]
        expected = common.sha256(systemui)
        output = (f"{apksigner_hash}  {builder.APKSIGNER}\n"
                  f"{jar_hash}  {builder.APKSIGNER_JAR}\n"
                  f"{expected}  /tmp/SystemUI.apk\n"
                  f"Signer #1 certificate SHA-256 digest: {PLATFORM_SIGNER}\n")
        def mutate(*args, **kwargs):
            systemui.write_bytes(b"changed-during-verification")
            return SimpleNamespace(returncode=0, stdout=output)
        with patch.object(builder, "inspect_image", return_value={"Id": tool_image}), \
                patch.object(builder.subprocess, "run", side_effect=mutate), \
                self.assertRaisesRegex(ValueError, "changed during"):
            builder.systemui_signer(self.product, receipt, expected)

    def test_exact_derived_layer_delta_rejects_intervening_ancestor(self):
        layers = ["sha256:base"]
        config = {"User": "demo",
                  "Entrypoint": ["python3", "/opt/wonad/phase1-conformance-entrypoint.py"],
                  "Cmd": ["verify"],
                  "WorkingDir": "/state"}
        valid = {"RootFS": {"Layers": layers + ["run", "copy-root", "copy-bundle"]},
                 "Config": config}
        self.assertEqual(valid, builder.validate_derived_image({"RootFS": {"Layers": layers}}, valid))
        intervening = copy.deepcopy(valid)
        intervening["RootFS"]["Layers"].insert(1, "unreviewed-intermediate")
        with self.assertRaisesRegex(ValueError, "ancestry"):
            builder.validate_derived_image({"RootFS": {"Layers": layers}}, intervening)

    def test_exact_derived_layer_delta_accepts_only_final_workdir_empty_layer(self):
        empty = "sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"
        layers = ["sha256:base"]
        delta = ["sha256:run", "sha256:copy-root", "sha256:copy-bundle"]
        config = {"User": "demo",
                  "Entrypoint": ["python3", "/opt/wonad/phase1-conformance-entrypoint.py"],
                  "Cmd": ["verify"],
                  "WorkingDir": "/state"}
        observed = {"RootFS": {"Layers": layers + delta + [empty]}, "Config": config}
        self.assertEqual(observed,
                         builder.validate_derived_image({"RootFS": {"Layers": layers}}, observed))

        for bad_delta in (
                [empty, *delta],
                [delta[0], empty, *delta[1:]],
                [*delta, empty, empty],
                [*delta, "sha256:foreign-fourth"],
        ):
            with self.subTest(delta=bad_delta), self.assertRaisesRegex(ValueError, "ancestry"):
                builder.validate_derived_image(
                    {"RootFS": {"Layers": layers}},
                    {"RootFS": {"Layers": layers + bad_delta}, "Config": config})

        wrong_workdir = copy.deepcopy(observed)
        wrong_workdir["Config"]["WorkingDir"] = "/tmp"
        with self.assertRaisesRegex(ValueError, "configuration"):
            builder.validate_derived_image({"RootFS": {"Layers": layers}}, wrong_workdir)

    def test_build_candidate_rechecks_tag_immediately_before_publication(self):
        output = self.root / "tag-race-stage"; output.mkdir()
        candidate = "sha256:" + "a" * 64
        base_image = "sha256:" + "d" * 64
        tag = "wonad:phase1-conformance-candidate-tag-race"
        manifest = {"schema": 1, "test": "tag-race"}

        def docker_run(argv, **_kwargs):
            if argv[:2] == ["docker", "build"]:
                Path(argv[argv.index("--iidfile") + 1]).write_text(candidate + "\n")
            return SimpleNamespace(returncode=0, stdout="")

        with patch.object(builder, "verify_packet", return_value=self.receipt), \
                patch.object(builder, "base_manifest", return_value=self.base), \
                patch.object(builder, "systemui_signer", return_value=PLATFORM_SIGNER), \
                patch.object(builder, "promotion_base", return_value=({}, "base-ref")), \
                patch.object(builder, "stage", return_value=manifest), \
                patch.object(builder, "inspect_image", return_value={"Id": base_image}), \
                patch.object(builder, "validate_derived_image"), \
                patch.object(builder.subprocess, "run", side_effect=docker_run) as run, \
                patch.object(builder.subprocess, "check_output", side_effect=[
                    "", "Verifying fresh-guest Phase-1 conformance candidate…\n" +
                    json.dumps(manifest)]) as check_output, \
                patch.object(builder.native, "publish_candidate",
                             side_effect=ValueError("Preserving existing candidate image tag")) as publish, \
                self.assertRaisesRegex(ValueError, "Preserving existing"):
            builder.build_candidate(self.product, self.packet, self.receipt_sha,
                                    output, base_image, tag)
        self.assertEqual(2, check_output.call_count)
        publish.assert_called_once_with(candidate, tag)
        self.assertFalse(any(call.args[0][:2] == ["docker", "tag"]
                             for call in run.call_args_list))


class StatusTests(unittest.TestCase):
    def test_complete_exact_status_passes(self):
        self.assertEqual(terminal(), common.validate_status(terminal(), "d" * 32, 3))

    def test_missing_operation_callback_or_facade_never_passes(self):
        for field, mutation in (
            ("operations", lambda value: value.pop()),
            ("callbacks", lambda value: value.__setitem__("onResult", 0)),
            ("facades", lambda value: value.pop()),
        ):
            value = terminal(); mutation(value[field])
            with self.subTest(field=field), self.assertRaises(common.ConformanceError):
                common.validate_status(value)

    def test_extra_capability_display_or_duplicate_facade_never_passes(self):
        for field, mutation in (
            ("capabilities", lambda value: value.__setitem__("capabilities", value["capabilities"] | 1)),
            ("display_ids", lambda value: value["display_ids"].append(4)),
            ("facades", lambda value: value["facades"].append(value["facades"][0])),
        ):
            value = terminal(); mutation(value)
            with self.subTest(field=field), self.assertRaises(common.ConformanceError):
                common.validate_status(value, display_id=3)

    def test_bool_cannot_impersonate_integer_api_or_generation(self):
        for field in ("api_version", "generation", "heartbeat_count"):
            value = terminal(); value[field] = True
            with self.subTest(field=field), self.assertRaises(common.ConformanceError):
                common.validate_status(value)


class AcceptanceTests(Fixture):
    container = "2" * 64
    image = "sha256:" + "3" * 64
    boot = "12345678-1234-1234-1234-123456789abc"
    run_id = "4" * 32
    container_run = "5" * 32
    display = 3

    def row(self, argv, tick, output="", *, evidence=None, output_sha256=None):
        value = {"argv": argv, "returncode": 0, "started_monotonic_ns": tick,
                 "ended_monotonic_ns": tick + 1}
        if evidence is None: value["output"] = output
        else: value.update(evidence=evidence, output_sha256=output_sha256)
        return value

    def evidence_fixture(self):
        ordinal = getattr(self, "_evidence_ordinal", 0) + 1
        self._evidence_ordinal = ordinal
        stage, manifest = self.stage("candidate-stage-%d" % ordinal)
        directory = self.root / ("evidence-%d" % ordinal); directory.mkdir()
        producer = guest.Producer(self.image, self.product, self.packet, self.receipt_sha, directory)
        producer.seal_prelaunch_userdata()
        local_row = producer.trace[0]
        (directory / "image-manifest.json").write_bytes(common.canonical(manifest))
        shutil = __import__("shutil")
        shutil.copyfile(stage / "product-candidate-manifest.json", directory / "product-candidate-manifest.json")
        shutil.copyfile(self.packet / "receipt.json", directory / "packet-receipt.json")
        status = terminal(self.run_id, self.display)
        (directory / "terminal-status.json").write_bytes(common.canonical(status))
        (directory / "conformance.log").write_text(json.dumps(status, sort_keys=True) + "\n")
        (directory / "display.txt").write_text("mDisplayId=0\nmDisplayId=3\n")
        (directory / "protected-events.txt").write_text("--------- beginning of events\n")
        hierarchy = ('<?xml version="1.0"?><hierarchy><node package="com.android.systemui" '
                     'text="Enable Wonad desktop" enabled="true" clickable="true" '
                     'bounds="[100,100][200,200]" /></hierarchy>')
        (directory / "consent-hierarchy.xml").write_text(hierarchy)
        (directory / acceptance.PHONE_HOME_ACTIVITIES).write_text(phone_home_activities())
        (directory / acceptance.PHONE_HOME_WINDOWS).write_text(phone_home_windows())
        processes = {"system_server": {"pid": 101, "start_ticks": 1001},
                     "com.android.systemui": {"pid": 202, "start_ticks": 1002},
                     "com.android.launcher3": {"pid": 303, "start_ticks": 1003},
                     "com.android.phone": {"pid": 404, "start_ticks": 1004}}
        installed = {FIXTURE: {"path": "/data/app/fixture/base.apk", "sha256": self.artifacts["fixture"]["sha256"]},
                     APP: {"path": "/data/app/conformance/base.apk", "sha256": self.artifacts["conformance"]["sha256"]}}
        base_state = {"boot_id": self.boot, "fingerprint": FINGERPRINT, "abi": "x86_64",
            "enforcing": "Enforcing", "current_user": "0", "consent": "1",
            "protected_processes": processes, "display_id": self.display, "os_artifacts": self.os_artifacts}
        before = {**base_state, "packages": {APP: None, FIXTURE: None, FAULT: None},
                  "installed": installed, "consent_point": [150, 150]}
        after = {**base_state,
            "packages": {APP: installed[APP]["path"], FIXTURE: installed[FIXTURE]["path"], FAULT: None},
            "installed": {**installed, FAULT: None}, "consent_point": None}
        (directory / "before.json").write_bytes(common.canonical(before))
        (directory / "after.json").write_bytes(common.canonical(after))

        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        trace, tick = [], producer.prelaunch_userdata["timeline"]["create_started_monotonic_ns"] - 4
        def add(argv, output="", **kwargs):
            nonlocal tick
            trace.append(self.row(argv, tick, output, **kwargs)); tick += 2
        def add_inspect(running):
            add(["docker", "container", "inspect", self.container], json.dumps([{
                "Id": self.container, "Image": self.image, "State": {"Running": running},
                "Config": {"Labels": {acceptance.LABEL: self.container_run}, "User": "1000:1000"},
                "Mounts": [{"Destination": "/state", "Source": str(directory / "emulator-state"),
                            "RW": True, "Type": "bind", "Mode": "rw,Z", "Propagation": "rprivate"}],
                "HostConfig": {"NetworkMode": "none", "Privileged": False, "PortBindings": {},
                    "Binds": [str(directory / "emulator-state") + ":/state:rw,Z"],
                    "CapAdd": None, "DeviceRequests": None, "DeviceCgroupRules": None,
                    "VolumesFrom": None, "PidMode": "", "IpcMode": "private", "CgroupnsMode": "private",
                    "UTSMode": "", "UsernsMode": "", "MemorySwap": 16 * 1024**3,
                    "MemoryReservation": 0,
                    "ReadonlyRootfs": False, "AutoRemove": False, "PublishAllPorts": False,
                    "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                    "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"], "GroupAdd": ["103"],
                    "Devices": [{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm",
                                 "CgroupPermissions": "rwm"}],
                    "PidsLimit": 1024, "Memory": 8 * 1024**3, "NanoCpus": 12_000_000_000,
                    "ShmSize": 512 * 1024**2, "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=2g"},
                    "Ulimits": [{"Name": "core", "Hard": 0, "Soft": 0},
                                {"Name": "nofile", "Hard": 65536, "Soft": 65536}]}}]))
        def add_process(name, epoch):
            pid = epoch["pid"]
            fields = ["1"] * 19
            fields[18] = str(epoch["start_ticks"])
            add(prefix + ["shell", "pidof", name], str(pid) + "\n")
            add(prefix + ["shell", "su", "0", "cat", f"/proc/{pid}/stat"],
                f"{pid} ({name}) S " + " ".join(fields) + "\n")
        def add_identity(summary):
            # Build both raw bundles with the real producer method rather than
            # another manually maintained copy of its observation ordering.
            outputs = {
                ("cat", "/proc/sys/kernel/random/boot_id"): summary["boot_id"],
                ("getprop", "ro.build.fingerprint"): summary["fingerprint"],
                ("getprop", "ro.product.cpu.abi"): summary["abi"],
                ("getenforce",): summary["enforcing"],
                ("am", "get-current-user"): summary["current_user"],
                ("settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"):
                    summary["consent"],
                **{("sha256sum", path): summary["os_artifacts"][role] + "  " + path
                   for role, path in guest.OS_GUEST_PATHS.items()},
            }
            producer = guest.Producer(self.image, self.product, self.packet, self.receipt_sha, directory)
            producer.manifest = manifest
            def observe(*args):
                command = tuple(map(str, args))
                output = outputs[command]
                add(prefix + ["shell", *command], output + "\n")
                return output
            with patch.object(producer, "shell", side_effect=observe):
                observed = producer.state_record(summary["packages"], summary["protected_processes"],
                    display_id=summary["display_id"], installed=summary["installed"],
                    consent_point=summary["consent_point"])
            self.assertEqual(summary, observed)
        add(["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs",
             "/tmp:rw,nosuid,size=64m", self.image, "verify"],
            "Verifying fresh-guest Phase-1 conformance candidate…\n" + json.dumps(manifest) + "\n")
        add(["docker", "run", "--rm", "--network", "none", "--read-only", "--entrypoint", "cat",
             self.image, "/opt/wonad/product-candidate-manifest.json"],
            (directory / "product-candidate-manifest.json").read_text())
        trace.append(local_row)
        tick = local_row["ended_monotonic_ns"] + 1
        add(["docker", "run", "-d", "--name", "wonad-phase1-conformance-" + self.container_run[:12],
             "--label", acceptance.LABEL + "=" + self.container_run, "--network", "none",
             "--device", "/dev/kvm", "--group-add", "103", "--user", "1000:1000",
             "--cap-drop=ALL", "--security-opt", "no-new-privileges=true", "--pids-limit", "1024",
             "--memory", "8g", "--cpus", "12", "--shm-size", "512m",
             "--ulimit", "nofile=65536:65536", "--ulimit", "core=0:0",
             "--tmpfs", "/tmp:rw,nosuid,nodev,size=2g",
             "--volume", str(directory / "emulator-state") + ":/state:rw,Z",
             "--env", "HOME=/state", "--env", "TMPDIR=/state/tmp",
             "--env", "WONAD_VIEWER_TRANSPORT=vnc", "--entrypoint", "python3",
             self.image, "/opt/wonad/session.py"], self.container + "\n")
        add_inspect(True)
        add_inspect(True)
        add(prefix + ["shell", "getprop", "sys.boot_completed"], "1\n")
        for package in (APP, FIXTURE, FAULT): add(prefix + ["shell", "pm", "path", package], "")
        add(prefix + ["shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"],
            "  KeyguardStateController:\n    mShowing: false\n    mSecure: false\n"
            "    mCanDismissLockScreen: true\n")
        add(prefix + ["shell", "am", "get-current-user"], "0\n")
        add(prefix + ["shell", "pm", "list", "users"], "Users:\n\tUserInfo{0:Owner:13} running\n")
        for name, epoch in processes.items():
            add_process(name, epoch)
        add(prefix + ["emu", "multidisplay", "add", "1", "1920", "1080", "160", "132165"], "OK\n")
        add(prefix + ["shell", "dumpsys", "display"], (directory / "display.txt").read_text())
        add(prefix + ["install", "--user", "0", "/opt/wonad/phase1-conformance/fixture.apk"], "Success\n")
        add(prefix + ["shell", "pm", "path", FIXTURE], "package:" + installed[FIXTURE]["path"] + "\n")
        add(prefix + ["shell", "sha256sum", installed[FIXTURE]["path"]],
            installed[FIXTURE]["sha256"] + "  " + installed[FIXTURE]["path"] + "\n")
        add(prefix + ["install", "--user", "0", "/opt/wonad/phase1-conformance/conformance.apk"], "Success\n")
        add(prefix + ["shell", "pm", "path", APP], "package:" + installed[APP]["path"] + "\n")
        add(prefix + ["shell", "sha256sum", installed[APP]["path"]],
            installed[APP]["sha256"] + "  " + installed[APP]["path"] + "\n")
        add(prefix + ["shell", "pm", "path", FAULT], "")
        for package, uid in ((FIXTURE, 10181), (APP, 10180)):
            identity = "package:%s uid:%d\n" % (package, uid)
            add(prefix + ["shell", "cmd", "package", "list", "packages", "-U",
                          "--user", "0", package], identity)
            add(prefix + ["shell", "cmd", "package", "list", "packages", "-U",
                          "--user", "0", "--uid", str(uid)], identity)
        add(prefix + ["shell", "settings", "--user", "0", "get", "secure",
                      "wonad_external_desktop_enabled"], "null\n")
        add(prefix + ["shell", "am", "start", "-W", "--display", "0", "-n",
                      "com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity"], "Status: ok\n")
        remote = "/data/local/tmp/wonad-phase1-consent-" + self.container_run + ".xml"
        add(prefix + ["shell", "uiautomator", "dump", "--compressed", remote],
            "UI hierchary dumped to: " + remote + "\n")
        add(prefix + ["exec-out", "cat", remote], hierarchy + "\n")
        add(prefix + ["shell", "rm", "--", remote], "")
        add(prefix + ["shell", "input", "touchscreen", "-d", "0", "tap", "150", "150"], "")
        add(prefix + ["shell", "settings", "--user", "0", "get", "secure",
                      "wonad_external_desktop_enabled"], "1\n")
        add(prefix + ["shell", "cmd", "package", "resolve-activity", "--components",
                      "--user", "0", "-a", acceptance.HOME_ACTION, "-c",
                      acceptance.HOME_CATEGORY], HOME_COMPONENT + "\n")
        add(prefix + ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
        add(prefix + ["shell", "dumpsys", "activity", "activities"],
            (directory / acceptance.PHONE_HOME_ACTIVITIES).read_text())
        add(prefix + ["shell", "dumpsys", "window", "windows"],
            (directory / acceptance.PHONE_HOME_WINDOWS).read_text())
        add_identity(before)
        add(["docker", "exec", self.container, "python3",
             "/opt/wonad/phase1-conformance/conformance_smoke.py", "--adb", "adb", "--serial", acceptance.SERIAL,
             "--display-id", str(self.display), "--timeout", "360"], evidence="conformance.log",
            output_sha256=common.sha256(directory / "conformance.log"))
        add(prefix + ["shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"],
            "WONAD_CONFORMANCE_STATUS " + json.dumps(status, sort_keys=True) + "\n")
        for package in (APP, FIXTURE, FAULT):
            add(prefix + ["shell", "pm", "path", package],
                "" if package == FAULT else "package:" + installed[package]["path"] + "\n")
        for name, epoch in processes.items():
            add_process(name, epoch)
        for package in (APP, FIXTURE):
            add(prefix + ["shell", "sha256sum", installed[package]["path"]],
                installed[package]["sha256"] + "  " + installed[package]["path"] + "\n")
        add_identity(after)
        add(prefix + ["shell", "logcat", "-b", "events", "-d", "-v", "threadtime",
                      "am_anr:I", "am_crash:I", "*:S"], evidence="protected-events.txt",
            output_sha256=common.sha256(directory / "protected-events.txt"))
        add_inspect(True)
        add(["docker", "stop", "-t", "30", self.container], self.container + "\n")
        add_inspect(False)
        (directory / "commands.json").write_bytes(common.canonical(trace))
        records = {path.name: common.file_ref(path) for path in directory.iterdir() if path.is_file()}
        report = {"schema": 1, "kind": common.REPORT_KIND, "scope": common.REPORT_SCOPE,
            "status": "passed", "api": 3, "run": self.run_id, "image_id": self.image,
            "fingerprint": FINGERPRINT, "container": self.container,
            "container_run": self.container_run, "boot_id": self.boot,
            "display_id": self.display, "packet_receipt_sha256": self.receipt_sha,
            "product_images": manifest["product_images"], "os_artifacts": manifest["os_artifacts"],
            "artifacts": manifest["artifacts"], "terminal_status": status,
            "gates": {"fresh_userdata_and_absent_packages": "passed", "ordinary_ui_consent": "passed",
                "full_v3_operations_callbacks_capabilities_and_facades": "passed",
                "protected_process_continuity": "passed",
                "platform_fault_injection": "identity_verified_only_not_run"},
            "runtime_qualified": False, "qualification_claimed": False, "fault_apk_installed": False,
            "downgrade_or_uninstall_used": False, "settings_state_seeded": False,
            "container_stopped": True, "userdata_retained_path": str(directory / "emulator-state"),
            "evidence_files": records}
        (directory / "report.json").write_bytes(common.canonical(report))
        return directory, report

    def audit(self, directory):
        with patch.object(acceptance.packet_tool, "validate_receipt", return_value=None):
            return acceptance.audit_report(directory / "report.json", self.product, self.packet,
                                           self.receipt_sha, external_checks=False)

    def rewrite_evidence(self, directory, name, value):
        (directory / name).write_bytes(common.canonical(value))
        report = common.load(directory / "report.json")
        report["evidence_files"][name] = common.file_ref(directory / name)
        (directory / "report.json").write_bytes(common.canonical(report))

    def rewrite_trace(self, directory, trace):
        record = common.load(directory / "prelaunch-userdata.json")
        tick = record["timeline"]["create_started_monotonic_ns"] - len(trace) * 2 - 10
        for row in trace:
            if row.get("kind") == "local_evidence":
                tick = row["ended_monotonic_ns"] + 1
                continue
            row["started_monotonic_ns"] = tick
            duration = 10_000_000_000 if row.get("timed_out") else 1
            row["ended_monotonic_ns"] = tick + duration
            tick += duration + 1
        self.rewrite_evidence(directory, "commands.json", trace)

    def insert_boot_polls(self, trace, index, polls):
        inspections_and_polls = []
        for row in polls:
            inspections_and_polls.extend((copy.deepcopy(trace[index - 1]), row))
        trace[index - 1:index - 1] = inspections_and_polls

    def test_independent_auditor_accepts_exact_bounded_evidence(self):
        directory, _ = self.evidence_fixture()
        result = self.audit(directory)
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification", result["status"])
        self.assertEqual("not_run", result["fault_injection"])

    def test_real_producer_launch_is_accepted_without_a_synthetic_argv_copy(self):
        directory, _ = self.evidence_fixture()
        # Execute the production launch builder, but never start Docker or an
        # emulator. Only the external boundary and boot observations are fake.
        (directory / "emulator-state/tmp").rmdir()
        (directory / "emulator-state").rmdir()
        (directory / "prelaunch-userdata.json").unlink()
        producer = guest.Producer(self.image, self.product, self.packet,
                                  self.receipt_sha, directory)
        producer.run = self.container_run
        launches = []

        def launch(*args, **kwargs):
            self.assertEqual(("run", "-d", "--name"), args[:3])
            self.assertFalse(kwargs)
            launches.append(["docker", *map(str, args)])
            return self.container

        with patch.object(producer, "docker", side_effect=launch), \
                patch.object(producer, "owned", return_value={"State": {"Running": True}}), \
                patch.object(producer, "shell", return_value="1"), \
                patch.object(guest, "Path", return_value=SimpleNamespace(
                    stat=lambda: SimpleNamespace(st_gid=103))) as device_path, \
                patch.object(guest.os, "getuid", return_value=1000), \
                patch.object(guest.os, "getgid", return_value=1000):
            producer.start()
        device_path.assert_called_once_with("/dev/kvm")
        self.assertEqual(1, len(launches))
        self.assertEqual(2, launches[0].count("--ulimit"))
        self.assertEqual(1, launches[0].count("nofile=65536:65536"))
        self.assertEqual(1, launches[0].count("core=0:0"))
        trace = common.load(directory / "commands.json")
        recorded = next(row for row in trace if row.get("argv", [])[:3] == ["docker", "run", "-d"])
        recorded["argv"] = launches[0]
        trace = [producer.trace[0] if row.get("kind") == "local_evidence" else row for row in trace]
        self.rewrite_evidence(directory, "prelaunch-userdata.json", producer.prelaunch_userdata)
        self.rewrite_trace(directory, trace)
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification",
                         self.audit(directory)["status"])

    def test_real_producer_uses_user_zero_forward_and_reverse_uid_queries(self):
        directory = self.root / "uid-producer"; directory.mkdir()
        producer = guest.Producer(self.image, self.product, self.packet, self.receipt_sha, directory)
        fixture = "package:%s uid:10181" % FIXTURE
        app = "package:%s uid:10180" % APP
        with patch.object(producer, "shell", side_effect=[fixture, fixture, app, app]) as shell:
            self.assertEqual({FIXTURE: 10181, APP: 10180}, producer.package_identities())
        self.assertEqual([
            ("cmd", "package", "list", "packages", "-U", "--user", 0, FIXTURE),
            ("cmd", "package", "list", "packages", "-U", "--user", 0, "--uid", 10181),
            ("cmd", "package", "list", "packages", "-U", "--user", 0, APP),
            ("cmd", "package", "list", "packages", "-U", "--user", 0, "--uid", 10180),
        ], [call.args for call in shell.call_args_list])

    def test_real_consent_helper_returns_to_focused_phone_home_and_seals_raw_proof(self):
        directory = self.root / "consent-home-producer"; directory.mkdir()
        producer = guest.Producer(self.image, self.product, self.packet,
                                  self.receipt_sha, directory)
        producer.run = self.container_run
        hierarchy = ('<?xml version="1.0"?><hierarchy><node package="com.android.systemui" '
                     'text="Enable Wonad desktop" enabled="true" clickable="true" '
                     'bounds="[100,100][200,200]" /></hierarchy>')
        calls, settings = [], iter(("null", "1"))

        def shell(*args, **kwargs):
            calls.append(tuple(args))
            if args[:4] == ("settings", "--user", 0, "get"):
                value = next(settings)
            elif args[:3] == ("cmd", "package", "resolve-activity"):
                value = HOME_COMPONENT
            elif args == ("dumpsys", "activity", "activities"):
                value = phone_home_activities()
            elif args == ("dumpsys", "window", "windows"):
                value = phone_home_windows()
            else:
                value = "Status: ok"
            producer.trace.append({"output": value})
            return value

        with patch.object(producer, "shell", side_effect=shell), \
                patch.object(producer, "adb", return_value=hierarchy), \
                patch.object(guest.time, "sleep", return_value=None):
            self.assertEqual([150, 150], producer.enable_consent())
        resolve = next(index for index, call in enumerate(calls) if call[:3] ==
                       ("cmd", "package", "resolve-activity"))
        home = calls.index(("input", "keyboard", "-d", 0, "keyevent", "KEYCODE_HOME"))
        activities = calls.index(("dumpsys", "activity", "activities"))
        windows = calls.index(("dumpsys", "window", "windows"))
        self.assertLess(resolve, home); self.assertLess(home, activities); self.assertLess(activities, windows)
        self.assertEqual(phone_home_activities(),
                         (directory / guest.PHONE_HOME_ACTIVITIES).read_text())
        self.assertEqual(phone_home_windows(),
                         (directory / guest.PHONE_HOME_WINDOWS).read_text())

    def test_home_parser_rejects_visible_launcher_when_settings_remains_focused(self):
        activities = phone_home_activities().replace(
            "mCurrentFocus=Window{123abc u0 " + HOME_FULL_COMPONENT,
            "mCurrentFocus=Window{123abc u0 " + guest.SETTINGS)
        with self.assertRaisesRegex(ValueError, "focused/resumed"):
            acceptance.phone_home_proof(HOME_COMPONENT, HOME_FULL_COMPONENT,
                                        activities, phone_home_windows())

    def test_producer_and_auditor_accept_stock_shaped_home_dump_excerpt(self):
        activities = stock_shaped_phone_home_activities()
        windows = stock_shaped_phone_home_windows()
        guest.phone_home_proof(HOME_COMPONENT, HOME_FULL_COMPONENT, activities, windows)
        acceptance.phone_home_proof(HOME_COMPONENT, HOME_FULL_COMPONENT, activities, windows)

    def test_home_trace_rejects_missing_duplicate_stale_other_display_settings_nonhome_and_reordering(self):
        for attack in ("missing", "duplicate", "stale", "other_display", "settings",
                       "nonhome", "before_home"):
            with self.subTest(attack=attack):
                directory, _ = self.evidence_fixture()
                trace = common.load(directory / "commands.json")
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
                elif attack == "stale":
                    trace[activity]["output"] = phone_home_activities(state="STOPPED")
                elif attack == "other_display":
                    trace[window]["output"] = phone_home_windows(display=2, focused=2)
                elif attack == "settings":
                    trace[activity]["output"] = phone_home_activities().replace(
                        "mCurrentFocus=Window{123abc u0 " + HOME_FULL_COMPONENT,
                        "mCurrentFocus=Window{123abc u0 " + guest.SETTINGS)
                elif attack == "nonhome":
                    trace[activity]["output"] = phone_home_activities(activity_type="standard")
                else:
                    row = trace.pop(home)
                    window = next(index for index, item in enumerate(trace)
                                  if item.get("argv", [])[-3:] == ["dumpsys", "window", "windows"])
                    trace.insert(window + 1, row)
                self.rewrite_trace(directory, trace)
                with self.assertRaises(ValueError):
                    self.audit(directory)

    def test_home_trace_rejects_proof_exceeding_fifteen_seconds(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        self.rewrite_trace(directory, trace)
        trace = common.load(directory / "commands.json")
        home = next(index for index, row in enumerate(trace) if row.get("argv", [])[-7:] ==
                    ["shell", "input", "keyboard", "-d", "0", "keyevent", "KEYCODE_HOME"])
        window = next(index for index, row in enumerate(trace) if row.get("argv", [])[-3:] ==
                      ["dumpsys", "window", "windows"])
        trace[window]["ended_monotonic_ns"] = trace[home]["ended_monotonic_ns"] + 15_000_000_001
        cursor = trace[window]["ended_monotonic_ns"] + 1
        for row in trace[window + 1:]:
            duration = row["ended_monotonic_ns"] - row["started_monotonic_ns"]
            row["started_monotonic_ns"] = cursor
            row["ended_monotonic_ns"] = cursor + duration
            cursor = row["ended_monotonic_ns"] + 1
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "fifteen seconds"):
            self.audit(directory)

    def test_duplicate_resource_limits_are_not_accepted_after_resealing(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        launch = next(row.get("argv", []) for row in trace if row.get("argv", [])[:3] == ["docker", "run", "-d"])
        index = launch.index("--tmpfs")
        launch[index:index] = ["--ulimit", "nofile=65536:65536", "--ulimit", "core=0:0"]
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "isolated exact-image/fresh-state guest launch"):
            self.audit(directory)

    def test_owned_launch_must_return_the_reported_container_identity(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        row = next(row for row in trace if row.get("argv", [])[:3] == ["docker", "run", "-d"])
        row["output"] = "a" * 64 + "\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "owned Docker launch identity"):
            self.audit(directory)

    def test_stopped_inspection_must_follow_the_owned_stop(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace[-2], trace[-1] = trace[-1], trace[-2]
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "stop did not precede"):
            self.audit(directory)

    def test_stop_must_return_the_owned_container_identity(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace[-2]["output"] = "a" * 64 + "\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "stop did not precede"):
            self.audit(directory)

    def test_each_running_inspection_is_mandatory_and_must_observe_running(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        indices = [index for index, row in enumerate(original)
                   if row.get("argv", [])[:3] == ["docker", "container", "inspect"]][:-1]
        for index in indices:
            for mutation in ("missing", "already-stopped"):
                with self.subTest(position=index, mutation=mutation):
                    trace = copy.deepcopy(original)
                    if mutation == "missing":
                        trace.pop(index)
                    else:
                        inspect = json.loads(trace[index]["output"])
                        inspect[0]["State"]["Running"] = False
                        trace[index]["output"] = json.dumps(inspect)
                    self.rewrite_trace(directory, trace)
                    with self.assertRaisesRegex(ValueError, "inspection chronology|state contradicted"):
                        self.audit(directory)

    def test_extra_unconsumed_owned_inspection_is_not_silently_ignored(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace.insert(4, copy.deepcopy(trace[-1]))
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "inspection chronology"):
            self.audit(directory)

    def test_all_inspections_corroborate_actual_resource_and_security_profile(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        indices = [index for index, row in enumerate(original)
                   if row.get("argv", [])[:3] == ["docker", "container", "inspect"]]
        for index in indices:
            for field, bad in (("CapDrop", []), ("SecurityOpt", []), ("GroupAdd", []),
                    ("Devices", []), ("PidsLimit", 0), ("Memory", 0), ("NanoCpus", 0),
                    ("ShmSize", 0), ("Tmpfs", {}), ("Ulimits", [])):
                with self.subTest(position=index, field=field):
                    trace = copy.deepcopy(original)
                    inspect = json.loads(trace[index]["output"])
                    inspect[0]["HostConfig"][field] = bad
                    trace[index]["output"] = json.dumps(inspect)
                    self.rewrite_trace(directory, trace)
                    with self.assertRaisesRegex(ValueError, "resource.*profile|resource limits"):
                        self.audit(directory)

    def test_ulimit_order_is_not_significant_but_duplicate_names_or_booleans_are_rejected(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        reordered = copy.deepcopy(original)
        for row in reordered:
            if row.get("argv", [])[:3] == ["docker", "container", "inspect"]:
                inspect = json.loads(row["output"])
                inspect[0]["HostConfig"]["Ulimits"].reverse()
                row["output"] = json.dumps(inspect)
        self.rewrite_trace(directory, reordered)
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification",
                         self.audit(directory)["status"])
        for mutation in ("duplicate", "bool"):
            with self.subTest(mutation=mutation):
                trace = copy.deepcopy(original)
                row = trace[-1]
                inspect = json.loads(row["output"])
                limits = inspect[0]["HostConfig"]["Ulimits"]
                if mutation == "duplicate":
                    limits[1] = copy.deepcopy(limits[0])
                else:
                    limits[0]["Soft"] = False
                row["output"] = json.dumps(inspect)
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "resource.*profile|resource limits"):
                    self.audit(directory)

    def test_hidden_privilege_namespace_or_unbounded_swap_expansions_are_rejected(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for field, bad in (("CapAdd", ["SYS_ADMIN"]), ("DeviceRequests", [{}]),
                ("DeviceCgroupRules", ["a *:* rwm"]), ("VolumesFrom", ["foreign"]),
                ("PidMode", "host"), ("IpcMode", "host"), ("CgroupnsMode", "host"),
                ("UTSMode", "host"), ("UsernsMode", "host"), ("MemorySwap", -1),
                ("AutoRemove", True), ("PublishAllPorts", True),
                ("MemoryReservation", False), ("PortBindings", False),
                ("RestartPolicy", {"Name": "no", "MaximumRetryCount": False}),
                ("RestartPolicy", {"Name": "always", "MaximumRetryCount": 0})):
            with self.subTest(field=field):
                trace = copy.deepcopy(original)
                inspect = json.loads(trace[-1]["output"])
                inspect[0]["HostConfig"][field] = bad
                trace[-1]["output"] = json.dumps(inspect)
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "privilege/namespace/swap isolation"):
                    self.audit(directory)

    def test_state_mount_must_be_the_exact_private_bind_not_another_mount_kind(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for field, bad in (("Type", "volume"), ("Mode", "rw"), ("Propagation", "shared"),
                           ("Binds", ["/another/state:/state:rw,Z"])):
            with self.subTest(field=field):
                trace = copy.deepcopy(original)
                row = trace[-1]
                inspect = json.loads(row["output"])
                if field == "Binds":
                    inspect[0]["HostConfig"][field] = bad
                else:
                    inspect[0]["Mounts"][0][field] = bad
                row["output"] = json.dumps(inspect)
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "identity/isolation/resource profile"):
                    self.audit(directory)

    def test_prelaunch_record_is_mandatory_not_a_freshness_boolean(self):
        directory, _ = self.evidence_fixture()
        record = common.load(directory / "prelaunch-userdata.json")
        record["userdata_freshly_created"] = True
        self.reseal_prelaunch(directory, record)
        with self.assertRaisesRegex(ValueError, "Malformed canonical prelaunch"):
            self.audit(directory)

    def reseal_prelaunch(self, directory, record):
        self.rewrite_evidence(directory, "prelaunch-userdata.json", record)
        trace = common.load(directory / "commands.json")
        for row in trace:
            if row.get("kind") == "local_evidence":
                row.update(output_sha256=common.sha256(directory / "prelaunch-userdata.json"),
                           bytes=(directory / "prelaunch-userdata.json").stat().st_size)
        self.rewrite_evidence(directory, "commands.json", trace)

    def test_prelaunch_inventory_cannot_include_inherited_userdata_or_sentinels(self):
        directory, _ = self.evidence_fixture()
        record = common.load(directory / "prelaunch-userdata.json")
        record["inventory"][0]["children"] = [{"path": "old-session", "kind": "file"}]
        self.reseal_prelaunch(directory, record)
        with self.assertRaisesRegex(ValueError, "inventory was not exactly"):
            self.audit(directory)

    def test_prelaunch_record_binds_current_reviewed_producer_authority(self):
        directory, _ = self.evidence_fixture()
        record = common.load(directory / "prelaunch-userdata.json")
        record["authority"]["runner"]["sha256"] = "0" * 64
        self.reseal_prelaunch(directory, record)
        with self.assertRaisesRegex(ValueError, "reviewed API guest implementation"):
            self.audit(directory)

    def test_prelaunch_state_and_tmp_inodes_cannot_be_replaced(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "prelaunch-userdata.json")
        for name in ("state", "tmp"):
            with self.subTest(directory=name):
                record = copy.deepcopy(original)
                record[name]["ino"] += 1
                self.reseal_prelaunch(directory, record)
                with self.assertRaisesRegex(ValueError, "identity/ownership differs"):
                    self.audit(directory)

    def test_prelaunch_creation_must_be_after_offline_reads_and_before_launch(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "prelaunch-userdata.json")
        for malformed in ("before-offline", "after-launch"):
            with self.subTest(timeline=malformed):
                record = copy.deepcopy(original)
                if malformed == "before-offline":
                    record["timeline"]["create_started_monotonic_ns"] = 1
                else:
                    record["timeline"]["inventory_observed_monotonic_ns"] += 10**12
                self.reseal_prelaunch(directory, record)
                with self.assertRaisesRegex(ValueError, "before offline product|before launch"):
                    self.audit(directory)

    def test_prelaunch_local_row_cannot_be_omitted_or_unbound(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for mutation in ("missing", "digest", "bytes"):
            with self.subTest(mutation=mutation):
                trace = copy.deepcopy(original)
                local = next(row for row in trace if row.get("kind") == "local_evidence")
                if mutation == "missing":
                    trace.remove(local)
                elif mutation == "digest":
                    local["output_sha256"] = "0" * 64
                else:
                    local["bytes"] = True
                self.rewrite_evidence(directory, "commands.json", trace)
                with self.assertRaisesRegex(ValueError, "exact prelaunch seal|exact sealed bytes"):
                    self.audit(directory)

    def test_userdata_is_allowed_to_accumulate_normal_postboot_state(self):
        directory, _ = self.evidence_fixture()
        (directory / "emulator-state/tmp/runtime-log").write_bytes(b"normal boot output")
        (directory / "emulator-state/userdata.img").write_bytes(b"guest state")
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification",
                         self.audit(directory)["status"])

    def test_missing_raw_guest_observations_cannot_be_replaced_by_state_summaries(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for command in (
            ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            ["shell", "getprop", "ro.build.fingerprint"],
            ["shell", "getprop", "ro.product.cpu.abi"],
            ["shell", "getenforce"],
            ["shell", "sha256sum", "/system/framework/framework.jar"],
        ):
            with self.subTest(command=command):
                trace = copy.deepcopy(original)
                trace = [row for row in trace if row.get("argv", [])[-len(command):] != command]
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "raw guest|Raw guest"):
                    self.audit(directory)

    def test_wrong_raw_identity_cannot_be_hidden_by_matching_before_after_summaries(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for command, forged in (
            (["shell", "cat", "/proc/sys/kernel/random/boot_id"],
             "87654321-1234-1234-1234-123456789abc\n"),
            (["shell", "getprop", "ro.build.fingerprint"], "different/fingerprint\n"),
            (["shell", "getprop", "ro.product.cpu.abi"], "aarch64\n"),
            (["shell", "getenforce"], "Permissive\n"),
        ):
            with self.subTest(command=command):
                trace = copy.deepcopy(original)
                row = [row for row in trace if row.get("argv", [])[-len(command):] == command][-1]
                row["output"] = forged
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "Raw guest identity differs"):
                    self.audit(directory)

    def test_raw_os_hash_must_bind_both_the_expected_bytes_and_exact_path(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        path = "/system/framework/services.jar"
        for output in ("0" * 64 + "  " + path + "\n",
                       self.os_artifacts["os_services"] + "  /system/framework/other.jar\n"):
            with self.subTest(output=output):
                trace = copy.deepcopy(original)
                row = next(row for row in trace if row.get("argv", [])[-3:] == ["shell", "sha256sum", path])
                row["output"] = output
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "Raw guest OS bytes differ"):
                    self.audit(directory)

    def test_coherent_forged_installed_paths_cannot_override_native_package_readback(self):
        directory, _ = self.evidence_fixture()
        forged = "/data/app/forged/base.apk"
        before = common.load(directory / "before.json")
        before["installed"][APP]["path"] = forged
        self.rewrite_evidence(directory, "before.json", before)
        after = common.load(directory / "after.json")
        after["installed"][APP]["path"] = after["packages"][APP] = forged
        self.rewrite_evidence(directory, "after.json", after)
        with self.assertRaisesRegex(ValueError, "raw fresh-install path/bytes"):
            self.audit(directory)

    def test_initial_installed_hash_is_checked_not_only_the_terminal_hash(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        path = "/data/app/conformance/base.apk"
        row = next(row for row in trace if row.get("argv", [])[-3:] == ["shell", "sha256sum", path])
        row["output"] = "0" * 64 + "  " + path + "\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "raw fresh-install path/bytes"):
            self.audit(directory)

    def test_installed_client_uid_must_be_an_ordinary_active_user_application(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for uid in (1000, 20000, 99000, 110180):
            with self.subTest(uid=uid):
                trace = copy.deepcopy(original)
                forward = next(row for row in trace if
                               row.get("argv", [])[-4:] == ["-U", "--user", "0", APP])
                # Match the exact producer forward/reverse pair, changing both
                # so failure is the UID class rather than a superficial mismatch.
                forward["output"] = "package:%s uid:%d\n" % (APP, uid)
                reverse = next(row for row in trace if row.get("argv", [])[-2:] == ["--uid", "10180"])
                reverse["argv"][-1] = str(uid)
                reverse["output"] = forward["output"]
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "ordinary application UID"):
                    self.audit(directory)

    def test_installed_uid_reverse_owner_must_be_exact_singleton(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        mutations = []
        missing = copy.deepcopy(original)
        missing.pop(next(index for index, row in enumerate(missing)
                         if row.get("argv", [])[-2:] == ["--uid", "10180"]))
        mutations.append(missing)
        duplicate = copy.deepcopy(original)
        index = next(index for index, row in enumerate(duplicate)
                     if row.get("argv", [])[-1:] == [APP] and "--user" in row.get("argv", []))
        duplicate.insert(index + 1, copy.deepcopy(duplicate[index]))
        mutations.append(duplicate)
        aliased = copy.deepcopy(original)
        reverse = next(row for row in aliased if row.get("argv", [])[-2:] == ["--uid", "10180"])
        reverse["output"] += "package:%s uid:10180\n" % FIXTURE
        mutations.append(aliased)
        for ordinal, trace in enumerate(mutations):
            with self.subTest(mutation=ordinal):
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError,
                        "Package UID|package UID|unpaired package identity"):
                    self.audit(directory)

    def test_terminal_installed_hash_cannot_be_omitted(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        indices = [index for index, row in enumerate(trace)
                   if row.get("argv", [])[-3:] == ["shell", "sha256sum", "/data/app/conformance/base.apk"]]
        trace.pop(indices[-1])
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "terminal installed APK readback"):
            self.audit(directory)

    def test_service_dump_is_required_and_cannot_disagree_with_driver_status(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        command = ["shell", "dumpsys", "activity", "service", APP + "/.ConformanceService"]
        for remove in (True, False):
            with self.subTest(remove=remove):
                trace = copy.deepcopy(original)
                index = next(index for index, row in enumerate(trace) if row.get("argv", [])[-5:] == command)
                if remove:
                    trace.pop(index)
                else:
                    status = terminal(self.run_id, self.display)
                    status["generation"] += 1
                    trace[index]["output"] = "WONAD_CONFORMANCE_STATUS " + json.dumps(status) + "\n"
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "conformance service dump|Raw terminal service dump"):
                    self.audit(directory)

    def test_protected_events_must_cover_the_terminal_state_not_an_earlier_snapshot(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace) if row.get("evidence") == "protected-events.txt")
        events = trace.pop(index)
        boundary = next(index for index, row in enumerate(trace) if row.get("evidence") == "conformance.log")
        trace.insert(boundary, events)
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Protected events were not read after terminal state"):
            self.audit(directory)

    def test_extra_contradictory_identity_queries_cannot_escape_bundle_replay(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        for command, output in (
            (["shell", "getenforce"], "Permissive\n"),
            (["shell", "getprop", "ro.build.fingerprint"], "evil/fingerprint\n"),
            (["shell", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"], "0\n"),
        ):
            with self.subTest(command=command):
                trace = copy.deepcopy(original)
                index = next(index for index, row in enumerate(trace)
                             if row.get("evidence") == "protected-events.txt")
                trace.insert(index, self.row(prefix + command, 999, output))
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "identity observation|raw consent observation"):
                    self.audit(directory)

    def test_raw_sole_owner_and_initial_current_user_cannot_be_replaced_by_summaries(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        for command, output in (
            (["shell", "pm", "list", "users"],
             "Users:\n\tUserInfo{0:Owner:13} running\n\tUserInfo{10:Other:10}\n"),
            (["shell", "am", "get-current-user"], "10\n"),
        ):
            with self.subTest(command=command):
                trace = copy.deepcopy(original)
                row = next(row for row in trace if row.get("argv", [])[-len(command):] == command)
                row["output"] = output
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "sole active owner 0"):
                    self.audit(directory)

    def test_final_boot_poll_must_complete_even_when_summary_and_full_status_pass(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        row = next(row for row in trace if row.get("argv", [])[-3:] == ["shell", "getprop", "sys.boot_completed"])
        row["output"] = "0\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "boot poll did not complete"):
            self.audit(directory)

    def test_transient_boot_poll_failure_is_retained_but_final_success_is_required(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace)
                     if row.get("argv", [])[-3:] == ["shell", "getprop", "sys.boot_completed"])
        failed = copy.deepcopy(trace[index])
        failed.update(returncode=1, output="error: device offline\n")
        self.insert_boot_polls(trace, index, [failed])
        self.rewrite_trace(directory, trace)
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification",
                         self.audit(directory)["status"])

    def test_boot_polling_stops_at_first_success_not_a_later_recovery(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace)
                     if row.get("argv", [])[-3:] == ["shell", "getprop", "sys.boot_completed"])
        success, regression = copy.deepcopy(trace[index]), copy.deepcopy(trace[index])
        regression["output"] = "0\n"
        self.insert_boot_polls(trace, index, [success, regression])
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "boot poll did not complete"):
            self.audit(directory)

    def test_real_producer_typed_transient_boot_timeout_is_preserved_and_accepted(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace)
                     if row.get("argv", [])[-3:] == ["shell", "getprop", "sys.boot_completed"])
        command = trace[index]["argv"]
        producer = guest.Producer(self.image, self.product, self.packet, self.receipt_sha, directory)
        subprocess = __import__("subprocess")
        with patch.object(guest.subprocess, "run", side_effect=subprocess.TimeoutExpired(
                command, 10, output=b"waiting for device\n")):
            with self.assertRaises(subprocess.TimeoutExpired):
                producer.command(command, timeout=10, journal_timeout=True)
        self.insert_boot_polls(trace, index, [producer.trace[0]])
        self.rewrite_trace(directory, trace)
        self.assertEqual("accepted_fresh_guest_conformance_not_runtime_qualification",
                         self.audit(directory)["status"])

    def test_timeouts_are_not_allowed_for_nonboot_observations(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        row = next(row for row in trace if row.get("argv", [])[-2:] == ["shell", "getenforce"])
        row.update(returncode=None, timed_out=True, timeout_seconds=10)
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Malformed/overlapping command trace"):
            self.audit(directory)

    def test_typed_boot_timeout_must_observe_the_full_deadline(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace)
                     if row.get("argv", [])[-3:] == ["shell", "getprop", "sys.boot_completed"])
        timeout = copy.deepcopy(trace[index])
        timeout.update(returncode=None, timed_out=True, timeout_seconds=10)
        self.insert_boot_polls(trace, index, [timeout])
        self.rewrite_trace(directory, trace)
        timeout["ended_monotonic_ns"] = timeout["started_monotonic_ns"] + 1
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "ten-second deadline"):
            self.audit(directory)

    def test_duplicate_unexternalized_event_read_cannot_hide_a_later_protected_crash(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace) if row.get("evidence") == "protected-events.txt")
        duplicate = self.row(trace[index]["argv"], 999,
            "10-10 16:00:00.000 1000 1000 I am_crash: [0,0,com.android.systemui,0]\n")
        trace.insert(index + 1, duplicate)
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Protected events were not read after terminal state"):
            self.audit(directory)

    def test_consent_polling_cannot_continue_after_its_first_success(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        command = ["shell", "settings", "--user", "0", "get", "secure", "wonad_external_desktop_enabled"]
        index = next(index for index, row in enumerate(trace)
                     if row.get("argv", [])[-7:] == command and row.get("output", "").strip() == "1")
        contradiction = copy.deepcopy(trace[index])
        contradiction["output"] = "0\n"
        trace[index + 1:index + 1] = [contradiction, copy.deepcopy(trace[index])]
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "contradictory raw consent observation"):
            self.audit(directory)

    def test_late_display_or_keyguard_observation_cannot_contradict_claimed_terminal_state(self):
        directory, _ = self.evidence_fixture()
        original = common.load(directory / "commands.json")
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        for command, output in (
            (["shell", "dumpsys", "display"], "mDisplayId=0\n"),
            (["shell", "dumpsys", "activity", "service", "com.android.systemui/.SystemUIService"],
             "  KeyguardStateController:\n    mShowing: true\n    mSecure: true\n"
             "    mCanDismissLockScreen: false\n"),
        ):
            with self.subTest(command=command):
                trace = copy.deepcopy(original)
                boundary = next(index for index, row in enumerate(trace) if row.get("evidence") == "conformance.log")
                trace.insert(boundary + 1, self.row(prefix + command, 999, output))
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "exactly one selected external display|late phone keyguard"):
                    self.audit(directory)

    def test_final_attach_display_poll_must_be_the_sealed_selected_display(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        index = next(index for index, row in enumerate(trace) if row.get("argv", [])[-3:] == ["shell", "dumpsys", "display"])
        unselected = copy.deepcopy(trace[index])
        unselected["output"] = "mDisplayId=0\n"
        trace.insert(index + 1, unselected)
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "exactly one selected external display"):
            self.audit(directory)

    def test_offline_identity_checks_cannot_be_relocated_after_the_guest_execution(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace = trace[2:] + trace[:2]
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "did not precede guest launch"):
            self.audit(directory)

    def test_offline_verifier_output_cannot_be_forged_under_a_valid_command(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace[0]["output"] = "Verifying fresh-guest Phase-1 conformance candidate…\n{}\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Raw offline candidate/manifest readback"):
            self.audit(directory)

    def test_bundled_product_manifest_read_must_match_the_sealed_exact_base(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace[1]["output"] = "{}\n"
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Raw offline candidate/manifest readback"):
            self.audit(directory)

    def test_settings_seed_is_rejected_even_if_summary_says_false(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        prefix = ["docker", "exec", self.container, "adb", "-s", acceptance.SERIAL]
        trace.insert(-2, self.row(prefix + ["shell", "settings", "--user", "0", "put", "secure",
                                           "wonad_external_desktop_enabled", "1"], 999))
        for index, row in enumerate(trace):
            row["started_monotonic_ns"] = index * 2 + 1; row["ended_monotonic_ns"] = index * 2 + 2
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "settings seeding"):
            self.audit(directory)

    def test_replacement_install_is_rejected_even_if_summary_says_false(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        install = next(row for row in trace if row.get("argv", [""])[-1].endswith("fixture.apk"))
        install["argv"].insert(-1, "-r")
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "replacement"):
            self.audit(directory)

    def test_unreviewed_direct_guest_command_is_rejected_after_resealing(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        trace.insert(-2, self.row(["docker", "exec", self.container, "sh", "-c",
                                   "settings put secure wonad_external_desktop_enabled 1"], 999))
        for index, row in enumerate(trace):
            row["started_monotonic_ns"] = index * 2 + 1; row["ended_monotonic_ns"] = index * 2 + 2
        self.rewrite_evidence(directory, "commands.json", trace)
        with self.assertRaisesRegex(ValueError, "unreviewed direct command"):
            self.audit(directory)

    def test_extra_external_display_is_rejected_after_consistent_resealing(self):
        directory, _ = self.evidence_fixture()
        changed = "mDisplayId=0\nmDisplayId=3\nmDisplayId=4\n"
        (directory / "display.txt").write_text(changed)
        trace = common.load(directory / "commands.json")
        row = next(row for row in trace if row.get("argv", [])[-3:] == ["shell", "dumpsys", "display"])
        row["output"] = changed
        (directory / "commands.json").write_bytes(common.canonical(trace))
        report = common.load(directory / "report.json")
        report["evidence_files"]["display.txt"] = common.file_ref(directory / "display.txt")
        report["evidence_files"]["commands.json"] = common.file_ref(directory / "commands.json")
        (directory / "report.json").write_bytes(common.canonical(report))
        with self.assertRaisesRegex(ValueError, "exactly one selected external display"):
            self.audit(directory)

    def test_missing_callback_is_rejected_after_all_hashes_are_consistently_resealed(self):
        directory, report = self.evidence_fixture()
        value = terminal(self.run_id, self.display); value["callbacks"]["onResult"] = 0
        self.rewrite_evidence(directory, "terminal-status.json", value)
        (directory / "conformance.log").write_text(json.dumps(value, sort_keys=True) + "\n")
        current = common.load(directory / "report.json")
        current["terminal_status"] = value
        current["evidence_files"]["conformance.log"] = common.file_ref(directory / "conformance.log")
        trace = common.load(directory / "commands.json")
        command = next(row for row in trace if row.get("evidence") == "conformance.log")
        command["output_sha256"] = common.sha256(directory / "conformance.log")
        (directory / "commands.json").write_bytes(common.canonical(trace))
        current["evidence_files"]["commands.json"] = common.file_ref(directory / "commands.json")
        (directory / "report.json").write_bytes(common.canonical(current))
        with self.assertRaisesRegex(ValueError, "callback coverage"):
            self.audit(directory)

    def test_resealed_systemui_crash_event_is_not_hidden_by_stable_summary(self):
        directory, _ = self.evidence_fixture()
        (directory / "protected-events.txt").write_text(
            "10-10 16:00:00.000  1000  1000 I am_crash: [0,0,com.android.systemui,0]\n")
        trace = common.load(directory / "commands.json")
        command = next(row for row in trace if row.get("evidence") == "protected-events.txt")
        command["output_sha256"] = common.sha256(directory / "protected-events.txt")
        (directory / "commands.json").write_bytes(common.canonical(trace))
        report = common.load(directory / "report.json")
        report["evidence_files"]["protected-events.txt"] = common.file_ref(directory / "protected-events.txt")
        report["evidence_files"]["commands.json"] = common.file_ref(directory / "commands.json")
        (directory / "report.json").write_bytes(common.canonical(report))
        with self.assertRaisesRegex(ValueError, "crash/ANR"):
            self.audit(directory)

    def test_resealed_stable_process_summary_cannot_override_raw_restart(self):
        directory, _ = self.evidence_fixture()
        for name in ("before.json", "after.json"):
            value = common.load(directory / name)
            value["protected_processes"]["com.android.systemui"] = {
                "pid": 999, "start_ticks": 9999,
            }
            self.rewrite_evidence(directory, name, value)
        with self.assertRaisesRegex(ValueError, "Summarized protected-process epochs"):
            self.audit(directory)

    def test_phone_epoch_role_preserves_three_original_os_roles(self):
        names = ("system_server", "com.android.systemui", "com.android.launcher3", "com.android.phone")
        self.assertEqual(guest.PROTECTED_PROCESS_NAMES, names)
        self.assertEqual(acceptance.PROTECTED_PROCESS_NAMES, names)
        self.assertEqual(guest.PROTECTED, set(names))
        report = {"container_run": self.container_run}
        self.assertTrue(acceptance.reviewed_adb_command(["shell", "pidof", "com.android.phone"], report))
        self.assertFalse(acceptance.reviewed_adb_command(["shell", "pidof", "unreviewed.process"], report))
        self.assertFalse(acceptance.reviewed_adb_command(["shell", "su", "0", "kill", "404"], report))

    def test_phone_process_epoch_uses_only_adjacent_read_only_root_stat(self):
        producer = object.__new__(guest.Producer)
        stat = "404 (com.android.phone) S " + " ".join(["1"] * 18 + ["1004"]) + "\n"
        with patch.object(producer, "shell", side_effect=["404", stat]) as shell:
            self.assertEqual(producer.process("com.android.phone"), {"pid": 404, "start_ticks": 1004})
        self.assertEqual([call.args for call in shell.call_args_list],
            [("pidof", "com.android.phone"), ("su", "0", "cat", "/proc/404/stat")])
        for pidof in ("", "404 505", "404 404"):
            with self.subTest(pidof=pidof), patch.object(producer, "shell", return_value=pidof), \
                    self.assertRaisesRegex(ValueError, "Missing/ambiguous protected process"):
                producer.process("com.android.phone")
        for malformed in (stat.replace("404 (", "505 ("), stat.replace("1004", "0"), "not proc stat"):
            with self.subTest(stat=malformed), patch.object(producer, "shell", side_effect=["404", malformed]), \
                    self.assertRaisesRegex(ValueError, "Cannot identify protected process epoch"):
                producer.process("com.android.phone")

    def test_real_run_guest_samples_phone_before_attach_and_after_full_conformance(self):
        directory, _ = self.evidence_fixture()
        initial, final = common.load(directory / "before.json"), common.load(directory / "after.json")
        for changed in (False, True):
            with self.subTest(changed=changed):
                output = self.root / ("mocked-phone-run-" + str(changed)); output.mkdir()
                producer = guest.Producer(self.image, self.product, self.packet, self.receipt_sha, output)
                producer.manifest = common.load(directory / "image-manifest.json")
                producer.container = self.container
                steps = []
                status = terminal(self.run_id, self.display)
                def shell(*args, **kwargs):
                    steps.append(args)
                    if args == ("am", "get-current-user"): return "0"
                    if args == ("pm", "list", "users"): return "UserInfo{0:Owner:13}"
                    if args[0] == "pidof": return str(initial["protected_processes"][args[1]]["pid"])
                    if args[:3] == ("su", "0", "cat"):
                        pid = int(args[3].split("/")[2])
                        name, epoch = next((name, epoch) for name, epoch in initial["protected_processes"].items()
                                           if epoch["pid"] == pid)
                        ticks = epoch["start_ticks"] + int(changed and name == "com.android.phone" and "driver" in steps)
                        return f"{pid} ({name}) S " + " ".join(["1"] * 18 + [str(ticks)]) + "\n"
                    if args[:4] == ("dumpsys", "activity", "service", APP + "/.ConformanceService"):
                        return "WONAD_CONFORMANCE_STATUS " + json.dumps(status)
                    if args[0] == "sha256sum":
                        package = next(package for package in (APP, FIXTURE) if final["packages"][package] == args[1])
                        return final["installed"][package]["sha256"] + "  " + args[1]
                    if args[0] == "logcat":
                        (output / kwargs["evidence"]).write_text("--------- beginning of events\n")
                        return ""
                    raise AssertionError("Unmocked guest command: " + str(args))
                def attach():
                    steps.append("attach"); return self.display
                def docker(*args, **kwargs):
                    steps.append("driver")
                    (output / "conformance.log").write_text(json.dumps(status) + "\n")
                def state(packages, processes, **kwargs):
                    template = final if FAULT in kwargs["installed"] else initial
                    return {**copy.deepcopy(template), "protected_processes": processes}
                with patch.object(producer, "packages", side_effect=[initial["packages"], final["packages"]]), \
                     patch.object(producer, "unlock"), patch.object(producer, "shell", side_effect=shell), \
                     patch.object(producer, "attach_display", side_effect=attach), \
                     patch.object(producer, "install", side_effect=lambda role, package: initial["installed"][package]), \
                     patch.object(producer, "package_path", return_value=None), \
                     patch.object(producer, "package_identities"), \
                     patch.object(producer, "enable_consent", return_value=initial["consent_point"]), \
                     patch.object(producer, "state_record", side_effect=state), \
                     patch.object(producer, "docker", side_effect=docker):
                    if changed:
                        with self.assertRaisesRegex(ValueError, "changed boot/protected processes"):
                            producer.run_guest()
                    else:
                        before, after, observed = producer.run_guest()
                        self.assertEqual(before["protected_processes"]["com.android.phone"],
                                         after["protected_processes"]["com.android.phone"])
                        self.assertEqual(observed, status)
                phone = [index for index, step in enumerate(steps) if step == ("pidof", "com.android.phone")]
                self.assertEqual(len(phone), 2)
                self.assertLess(phone[0], steps.index("attach"))
                self.assertGreater(phone[1], steps.index("driver"))

    def test_phone_epoch_cannot_be_omitted_from_either_state_summary(self):
        for side in ("before", "after"):
            with self.subTest(side=side):
                directory, _ = self.evidence_fixture()
                value = common.load(directory / (side + ".json"))
                del value["protected_processes"]["com.android.phone"]
                self.rewrite_evidence(directory, side + ".json", value)
                with self.assertRaisesRegex(ValueError, "Malformed fresh-guest state"):
                    self.audit(directory)

    def test_phone_epoch_replacement_and_pid_reuse_fail_independent_audit(self):
        for epoch in ({"pid": 505, "start_ticks": 1005}, {"pid": 404, "start_ticks": 1005}):
            with self.subTest(epoch=epoch):
                directory, _ = self.evidence_fixture()
                after = common.load(directory / "after.json")
                after["protected_processes"]["com.android.phone"] = epoch
                self.rewrite_evidence(directory, "after.json", after)
                with self.assertRaisesRegex(ValueError, "protected-process identity changed"):
                    self.audit(directory)

    def test_phone_raw_epoch_cannot_be_hidden_by_resealed_stable_summaries(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        phone = [index for index, row in enumerate(trace)
                 if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
        trace[phone[-1] + 1]["output"] = trace[phone[-1] + 1]["output"].replace("1004", "1005")
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "Summarized protected-process epochs"):
            self.audit(directory)

    def test_phone_raw_pair_must_be_complete_unique_and_bracket_full_exercise(self):
        for mutation in ("omitted", "unpaired", "duplicate", "late_baseline"):
            with self.subTest(mutation=mutation):
                directory, _ = self.evidence_fixture()
                trace = common.load(directory / "commands.json")
                phone = [index for index, row in enumerate(trace)
                         if row.get("argv", [])[-3:] == ["shell", "pidof", "com.android.phone"]]
                index = phone[0]
                if mutation == "omitted":
                    del trace[index:index + 2]
                elif mutation == "unpaired":
                    trace[index + 1]["argv"][-1] = "/proc/505/stat"
                elif mutation == "duplicate":
                    trace[index:index] = copy.deepcopy(trace[index:index + 2])
                else:
                    pair = trace[index:index + 2]; del trace[index:index + 2]
                    attach = next(offset for offset, row in enumerate(trace)
                                  if "multidisplay" in row.get("argv", []))
                    trace[attach + 1:attach + 1] = pair
                self.rewrite_trace(directory, trace)
                with self.assertRaisesRegex(ValueError, "protected.process|Protected pid/proc"):
                    self.audit(directory)

    def test_phone_epoch_cannot_alias_another_protected_pid_or_use_boolean_starttime(self):
        for metric in ({"pid": 101, "start_ticks": 1004}, {"pid": 404, "start_ticks": True}):
            with self.subTest(metric=metric):
                directory, _ = self.evidence_fixture()
                before = common.load(directory / "before.json")
                before["protected_processes"]["com.android.phone"] = metric
                self.rewrite_evidence(directory, "before.json", before)
                with self.assertRaisesRegex(ValueError, "Malformed fresh-guest state"):
                    self.audit(directory)

    def test_resealed_telephony_failure_cannot_hide_behind_healthy_desktop_processes(self):
        self.assertIn("com.android.phone", guest.PROTECTED)
        for kind in ("am_anr", "am_crash"):
            for process in ("com.android.phone", "com.android.phone:worker"):
                with self.subTest(kind=kind, process=process):
                    directory, _ = self.evidence_fixture()
                    (directory / "protected-events.txt").write_text(
                        f"10-13 17:47:09.529 676 1500 I {kind}: "
                        f"[0,1399,{process},818429517,failed to complete startup]\n")
                    trace = common.load(directory / "commands.json")
                    command = next(row for row in trace if row.get("evidence") == "protected-events.txt")
                    command["output_sha256"] = common.sha256(directory / "protected-events.txt")
                    (directory / "commands.json").write_bytes(common.canonical(trace))
                    report = common.load(directory / "report.json")
                    report["evidence_files"]["protected-events.txt"] = common.file_ref(directory / "protected-events.txt")
                    report["evidence_files"]["commands.json"] = common.file_ref(directory / "commands.json")
                    (directory / "report.json").write_bytes(common.canonical(report))
                    with self.assertRaisesRegex(ValueError, "crash/ANR"):
                        self.audit(directory)

    def test_consent_hierarchy_readback_must_precede_the_tap(self):
        directory, _ = self.evidence_fixture()
        trace = common.load(directory / "commands.json")
        read_index = next(index for index, row in enumerate(trace)
                          if row.get("argv", [])[-3:-1] == ["exec-out", "cat"])
        tap_index = next(index for index, row in enumerate(trace)
                         if "tap" in row.get("argv", []))
        read = trace.pop(read_index)
        if read_index < tap_index:
            tap_index -= 1
        trace.insert(tap_index + 1, read)
        self.rewrite_trace(directory, trace)
        with self.assertRaisesRegex(ValueError, "genuine phone UI"):
            self.audit(directory)


if __name__ == "__main__":
    unittest.main()
