import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
from zipfile import ZipFile

import publish
from source import configure, git, settings_patch
from verify import digest, inventory, ota_timestamp, signature

BUILD = "2026112401"


class Checks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_configure_needs_no_controller_source_or_certificate(self):
        config = self.root / "packages/apps/Updater/res/values/config.xml"
        config.parent.mkdir(parents=True)
        config.write_text("https://releases.grapheneos.org/")
        configure(self.root)
        self.assertEqual(config.read_text(), publish.BASE)

    def test_settings_patch_requires_reviewed_clean_source_and_only_opens_chooser(self):
        app = self.root / "packages/apps/Settings"
        xml = app / "res/xml/special_access.xml"
        strings = app / "res/values/strings.xml"
        xml.parent.mkdir(parents=True)
        strings.parent.mkdir(parents=True)
        xml.write_text("""<PreferenceScreen xmlns:android="http://schemas.android.com/apk/res/android">
    <Preference>
    </Preference>

    <Preference
        android:key="computer_control_automation"
        />
</PreferenceScreen>
""")
        # Preserve the exact patch context, with the large strings file omitted.
        strings.write_text("""<resources>
    <!-- [CHAR_LIMIT=60] Label for special access screen -->
    <string name="special_access">Special app access</string>

    <!-- Title for the See more preference item in Special app access settings [CHAR LIMIT=30] -->
</resources>
""")
        git(app, "init", "-q")
        git(app, "add", "res")
        git(app, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-qm", "Upstream Settings")
        revision = git(app, "rev-parse", "HEAD")
        manifest = ET.fromstring(f'<manifest><project path="packages/apps/Settings" revision="{revision}" /></manifest>')
        with patch.dict("source.PINS", settings_revision=revision):
            folder, args = settings_patch(self.root, manifest)
            git(folder, "apply", *args)
            with self.assertRaisesRegex(ValueError, "pristine"):
                settings_patch(self.root, manifest)
        with patch.dict("source.PINS", settings_revision="f" * 40):
            with self.assertRaisesRegex(ValueError, "needs review"):
                settings_patch(self.root, manifest)
        ns = "{http://schemas.android.com/apk/res/android}"
        row = next(p for p in ET.parse(xml).getroot() if p.get(ns + "key") == "external_desktop")
        self.assertEqual([node.tag for node in row], ["intent"])
        target = row[0]
        self.assertEqual(target.attrib, {
            ns + "action": "android.intent.action.MAIN",
            ns + "targetPackage": "com.android.systemui",
            ns + "targetClass": "com.android.wm.shell.externaldesktop.ExternalDesktopSettingsActivity",
        })
        self.assertEqual(list(target), [])

    def test_asset_limit_and_order(self):
        out = self.root/"parts"
        src = self.root/"src"
        out.mkdir()
        src.mkdir()
        for size in (7, 8, 17):
            (src/str(size)).write_bytes(bytes(range(size)))
        files = publish.assets(src,out,8)
        self.assertTrue(all(p.stat().st_size < 8 for p in files))
        for size in (8,17):
            self.assertEqual(b"".join(p.read_bytes() for p in sorted(out.glob(str(size)+".part*"))),bytes(range(size)))

    def test_ota(self):
        meta = dict([("pre-device","frankel"),("ota-type","AB"),("post-build-incremental",BUILD),
                     ("post-build","brand/frankel/frankel:17/id/"+BUILD+":user/release-keys"),("post-timestamp","1234")])
        for delta in ({}, {"pre-device":"emu64x"}, {"pre-build":"old"}, {"ota-wipe":"yes"},
                      {"post-build-incremental":"other"}):
            zpath = self.root/"ota"
            with ZipFile(zpath,"w") as z:
                for path in ("payload.bin","payload_properties.txt"):
                    z.writestr(path,b"")
                z.writestr("META-INF/com/android/metadata","".join(k+"="+v+"\n" for k,v in (meta|delta).items()))
            if delta:
                with self.assertRaises(ValueError): ota_timestamp(zpath,BUILD)
            else: self.assertEqual(ota_timestamp(zpath,BUILD),1234)

    def test_channel_rejects_both_kinds_of_rollback(self):
        publish.newer(None,BUILD,123,"beta")
        publish.newer("2026112400 122 frankel beta",BUILD,123,"beta")
        for prev in [BUILD+" 122 frankel beta","2026112400 124 frankel beta","2026112400 122 frankel stable"]:
            with self.assertRaises(ValueError): publish.newer(prev,BUILD,123,"beta")

    def test_signed_inventory(self):
        d = self.root/"handoff"
        d.mkdir()
        names = ["build-number","source-commit","native-inputs-sha256","unsigned-inputs-sha256",
                 "controller.apk","styx.apk","xmonad.apk",f"frankel-ota_update-{BUILD}.zip",
                 f"frankel-install-{BUILD}.zip",f"frankel-install-{BUILD}.zip.sig"]
        for name in names: (d/name).write_text(name)
        sums = d/"SHA256SUMS"
        sums.write_text("".join(digest(d/name)+"  "+name+"\n" for name in names))
        key = self.root/"key"
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",key],check=True)
        (self.root/"allowed_signers").write_text("pixel10 "+key.with_suffix(".pub").read_text())
        namespace = "chapeltech-pixel10-release"
        subprocess.run(["ssh-keygen","-Y","sign","-f",key,"-n",namespace,sums],check=True,capture_output=True)
        signature(self.root,sums,d/"SHA256SUMS.sig",namespace)
        inventory(d,BUILD)
        (d/"controller.apk").write_text("changed")
        with self.assertRaises(ValueError): inventory(d,BUILD)
        sums.write_text("replacement")
        with self.assertRaises(subprocess.CalledProcessError): signature(self.root,sums,d/"SHA256SUMS.sig",namespace)

    def test_approval_gates(self):
        (self.root/BUILD).mkdir()
        with patch.dict(os.environ,dict(BUILD_NUMBER=BUILD,CHANNEL="stable",SOURCE_COMMIT="a"*40,
                SIGNED_ROOT=str(self.root),PUBLIC_TRUST=str(self.root),UNSIGNED_SUMS_SHA256="a"*64,OTA_BUCKET="bucket")), \
                patch.object(publish,"verify",return_value=123), patch.object(publish,"channel_text",return_value=None), \
                patch.object(publish,"visible",return_value=io.BytesIO(b"catalog")), \
                patch.object(publish,"verify_catalog",return_value={"min_os":BUILD,"max_os":BUILD}), \
                patch.object(publish.sp,"check_output",side_effect=AssertionError("unexpected publication")):
            with self.assertRaisesRegex(ValueError,"untested candidate"): publish.publish()

    def test_beta_only_moves_after_public_bytes_match(self):
        from urllib.error import HTTPError
        d = self.root/BUILD
        d.mkdir()
        payload = d/f"frankel-ota_update-{BUILD}.zip"
        payload.write_bytes(b"payload")
        (self.root/"avb_pkmd.bin").write_bytes(b"public")
        events = []
        class Response(io.BytesIO):
            status = 206
            headers = {"Content-Range":"bytes 0-0/7"}
        sha = "a"*40
        def cli(args, **kwargs):
            if args[0] == "aws":
                events.append(args[args.index("--key")+1])
                return ""
            query = " ".join(args)
            if "/tags --jq" in query: return ""
            if "/commits/" in query: return sha
            if "/releases/tags/" in query:
                paths = [payload,self.root/"avb_pkmd.bin",Path(publish.__file__).with_name("INSTALL.md")]
                return json.dumps({"draft":False,"assets":[{"name":p.name,"digest":"sha256:"+digest(p)} for p in paths]})
            if args[1]=="release": return ""
            raise AssertionError(args)
        for bad in (True,False):
            events.clear()
            def public(name, first=False):
                if "incremental" in name: raise HTTPError(name,404,"absent",{},None)
                return Response(b"wrong" if bad else b"payload")
            with patch.dict(os.environ,dict(BUILD_NUMBER=BUILD,CHANNEL="beta",SOURCE_COMMIT=sha,
                    SIGNED_ROOT=str(self.root),PUBLIC_TRUST=str(self.root),UNSIGNED_SUMS_SHA256="a"*64,OTA_BUCKET="bucket")), \
                    patch.object(publish,"verify",return_value=123), patch.object(publish,"channel_text",return_value=None), \
                    patch.object(publish,"visible",side_effect=public), patch.object(publish.sp,"check_output",side_effect=cli):
                if bad:
                    with self.assertRaisesRegex(ValueError,"publicly served"): publish.publish()
                    self.assertNotIn("frankel-beta",events)
                else:
                    publish.publish()
                    self.assertEqual(events,[payload.name,"frankel-beta"])
