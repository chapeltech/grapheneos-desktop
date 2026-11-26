import io
import json
import os
from pathlib import Path
import shutil
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

    def os_trust(self):
        files = [self.root / name for name in publish.OS_TRUST_ASSETS]
        for path in files:
            path.write_bytes(path.name.encode())
        return files

    def test_configure_needs_no_controller_source_or_certificate(self):
        updater = self.root / "packages/apps/Updater"
        config = updater / "res/values/config.xml"
        config.parent.mkdir(parents=True)
        config.write_text('<resources>\n    <string name="url" translatable="false">'
                          'https://releases.grapheneos.org/</string>\n</resources>\n')
        service = updater / "src/app/seamlessupdate/client/Service.java"
        service.parent.mkdir(parents=True)
        service.write_text('    private HttpsURLConnection fetchData(final Network network, final String path) throws IOException {\n'
                           '        final URL url = new URL(getString(R.string.url) + path);\n'
                           + 'fetchData(network, downloadFile)\n' * 5)
        fixture = '<manifest><project path="packages/apps/Updater" revision="fixture"/></manifest>'
        def git_fixture(path, *args):
            if args[:1] == ("show",): return fixture
            if args[:1] == ("status",): return ""
            if args[:1] == ("rev-parse",): return "fixture"
            raise AssertionError(args)
        with patch.dict("source.PINS", updater_revision="fixture"), patch("source.git", side_effect=git_fixture):
            configure(self.root)
            self.assertRaises(ValueError, configure, self.root)
        resources = {n.get("name"): n.text for n in ET.parse(config).getroot()}
        self.assertEqual(resources, {"url": publish.BASE, "ota_download_url": publish.PINS["ota_download_url"]})
        self.assertEqual(service.read_text().count("fetchPayload(network, downloadFile, targetIncremental)"), 5)
        self.assertNotIn("fetchData(network, downloadFile)", service.read_text())
        self.assertTrue(service.with_name("OtaUrls.java").is_file())

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
        names = ["build-number","source-commit","native-inputs-sha256","unsigned-inputs-sha256","ota-origin",
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
        (self.root/BUILD/f"frankel-ota_update-{BUILD}.zip").touch()
        self.os_trust()
        with patch.dict(os.environ,dict(BUILD_NUMBER=BUILD,CHANNEL="stable",SOURCE_COMMIT="a"*40,
                SIGNED_ROOT=str(self.root),PUBLIC_TRUST=str(self.root),UNSIGNED_SUMS_SHA256="a"*64,OTA_BUCKET="bucket")), \
                patch.object(publish,"verify",return_value=123), patch.object(publish,"channel_text",return_value=None), \
                patch.object(publish.pointers,"read",return_value=(None,None)), \
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
        trust = self.os_trust()
        events = []
        pushed = []
        predecessor = "2026112301"
        prior_channel = f"{predecessor} 122 frankel beta\n".encode()
        other_build = "2026112201"
        other_channel = f"{other_build} 120 frankel stable\n".encode()
        class Response(io.BytesIO):
            status = 206
            headers = {"Content-Range":"bytes 1-6/7"}
        sha = "a"*40
        def cli(args, **kwargs):
            query = " ".join(args)
            if "/tags --jq" in query: return ""
            if "/commits/" in query: return sha
            if "/releases --jq" in query: return "42"
            for previous in (predecessor, other_build):
                tag = "frankel-0.1-" + previous
                if query.endswith("/releases/tags/" + tag):
                    inventory = [{"name": p.name, "digest": "sha256:" + digest(p)} for p in trust]
                    if bad == "boot-key" and previous == predecessor:
                        inventory = [entry for entry in inventory if entry["name"] != "avb_pkmd.bin"]
                    if bad == "os-cert" and previous == other_build:
                        inventory[1]["digest"] = "sha256:" + "0" * 64
                    return json.dumps({"draft": False, "tag_name": tag, "assets": inventory})
            if "/releases/tags/" in query or "/releases/42" in query:
                paths = [payload,*trust,Path(publish.__file__).with_name("INSTALL.md")]
                inventory = [{"name":p.name,"digest":"sha256:"+digest(p)} for p in paths]
                draft = "/releases/42" in query
                if draft and bad == "draft":
                    inventory[0]["digest"] = "sha256:" + "0" * 64
                return json.dumps({"draft":draft,"prerelease":True,"target_commitish":sha,
                    "tag_name":"frankel-0.1-"+BUILD,"assets":inventory})
            if args[1]=="release":
                pushed.append(args[2])
                return ""
            raise AssertionError(args)
        for bad in ("boot-key", "os-cert", "draft", "incremental", "range", "range-bytes", "bytes", None, "first"):
            events.clear()
            pushed.clear()
            source = "2000010100" if bad == "first" else predecessor
            def public(name, resume_from=None):
                if name == f"frankel-incremental-{source}-{BUILD}.zip":
                    if bad == "incremental":
                        return Response(b"unexpected incremental")
                    raise HTTPError(name, 404, "absent", {}, None)
                self.assertEqual(name, payload.name)
                if resume_from is not None:
                    self.assertEqual(resume_from, 1)
                    reply = Response(b"broken" if bad == "range-bytes" else b"ayload")
                    if bad == "range":
                        reply.status = 200
                    return reply
                return Response(b"wrong" if bad == "bytes" else b"payload")
            with patch.dict(os.environ,dict(BUILD_NUMBER=BUILD,CHANNEL="beta",SOURCE_COMMIT=sha,
                    SIGNED_ROOT=str(self.root),PUBLIC_TRUST=str(self.root),UNSIGNED_SUMS_SHA256="a"*64,OTA_BUCKET="bucket")), \
                    patch.object(publish,"verify",return_value=123), patch.object(publish,"channel_text",return_value=None), \
                    patch.object(publish.pointers,"read",side_effect={
                        "frankel-beta": (None, None) if bad == "first" else (prior_channel, sha),
                        "frankel-stable": (None, None) if bad == "first" else (other_channel, "b" * 40),
                    }.__getitem__), \
                    patch.object(publish.pointers,"write",side_effect=lambda name, body, sha: events.append(name)), \
                    patch.object(publish.pointers,"wait_visible"), \
                    patch.object(publish,"visible",side_effect=public), patch.object(publish.sp,"check_output",side_effect=cli):
                if bad in ("boot-key", "os-cert"):
                    with self.assertRaisesRegex(ValueError, "OS signing identity differs"):
                        publish.publish()
                    self.assertFalse(pushed)
                    self.assertFalse(events)
                elif bad == "draft":
                    with self.assertRaisesRegex(ValueError,"assets differ"): publish.publish()
                    self.assertNotIn("edit", pushed)
                    self.assertFalse(events)
                elif bad in ("range", "range-bytes", "incremental"):
                    with self.assertRaisesRegex(ValueError, "incorrect OTA resume range|must return HTTP 404"):
                        publish.publish()
                    self.assertFalse(events)
                elif bad == "bytes":
                    with self.assertRaisesRegex(ValueError,"publicly served"): publish.publish()
                    self.assertNotIn("frankel-beta",events)
                else:
                    publish.publish()
                    self.assertEqual(events,["frankel-beta"])

    def test_github_payload_url_and_range(self):
        name = f"frankel-ota_update-{BUILD}.zip"
        with patch.object(publish, "urlopen") as open_url:
            open_url.return_value.url = "https://release-assets.githubusercontent.com/asset"
            publish.visible(name, 300)
            request = open_url.call_args.args[0]
            self.assertEqual(request.full_url, f"{publish.PINS['ota_download_url']}frankel-0.1-{BUILD}/{name}")
            self.assertEqual(request.headers["Range"], "bytes=300-")
            publish.visible("frankel-beta")
            self.assertEqual(open_url.call_args.args[0].full_url, publish.BASE + "frankel-beta")

    def test_documented_linux_install_verifies_split_factory_without_ota(self):
        folder = self.root
        install = folder / f"frankel-install-{BUILD}.zip"
        install.write_bytes(b"factory image bytes")
        sums = folder / "SHA256SUMS"
        sums.write_text(f"{digest(install)}  {install.name}\n" + "0" * 64 + "  not-downloaded-ota.zip\n")
        key = folder / "fixture-key"
        subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",key], check=True)
        (folder / "allowed_signers").write_text("pixel10 " + key.with_suffix(".pub").read_text())
        subprocess.run(["ssh-keygen","-Y","sign","-f",key,"-n","factory images",install],
                       check=True, capture_output=True)
        data = install.read_bytes()
        install.unlink()
        (folder / (install.name + ".part000")).write_bytes(data[:7])
        (folder / (install.name + ".part001")).write_bytes(data[7:])
        instructions = Path(publish.__file__).with_name("INSTALL.md").read_text()
        command = instructions.split("```bash\n", 1)[1].split("```", 1)[0]
        command = command.replace("build=YYYYMMDDNN", f"build={BUILD}")
        subprocess.run(["bash", "-c", command], cwd=folder, check=True, capture_output=True)
        self.assertEqual(install.read_bytes(), data)
        install.write_bytes(b"bad")
        self.assertNotEqual(subprocess.run(["bash","-c",command], cwd=folder, capture_output=True).returncode, 0)

    @unittest.skipUnless(shutil.which("javac") and shutil.which("java"), "requires the Android build JDK")
    def test_updater_url_builder(self):
        harness = self.root / "CheckUrls.java"
        harness.write_text(f"""
package app.seamlessupdate.client;
class CheckUrls {{
    public static void main(String[] args) throws Exception {{
        String raw = "{publish.BASE}", releases = "{publish.PINS["ota_download_url"]}";
        String build = "{BUILD}", full = "frankel-ota_update-" + build + ".zip";
        String delta = "frankel-incremental-2026112301-" + build + ".zip";
        for (String file : new String[] {{full, delta}}) {{
            if (!OtaUrls.payload(releases, build, file).toString().equals(
                    releases + "frankel-0.1-" + build + "/" + file)) throw new AssertionError(file);
        }}
        if (!OtaUrls.metadata(raw, "frankel-beta").toString().equals(raw + "frankel-beta"))
            throw new AssertionError();
        try {{
            OtaUrls.payload(releases, "2026112301", full);
            throw new AssertionError("wrong target accepted");
        }} catch (java.io.IOException expected) {{}}
        try {{
            OtaUrls.metadata(raw, "frankel-../../other");
            throw new AssertionError("invalid channel accepted");
        }} catch (java.io.IOException expected) {{}}
    }}
}}
""")
        subprocess.run(["javac", "-d", self.root, Path(publish.__file__).with_name("OtaUrls.java"), harness], check=True)
        subprocess.run(["java", "-cp", self.root, "app.seamlessupdate.client.CheckUrls"], check=True)
