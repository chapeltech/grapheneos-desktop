import base64
import io
import json
import os
from pathlib import Path
import subprocess as sp
import tempfile
import unittest
from unittest.mock import patch

import apps


class AppsTests(unittest.TestCase):
    BUILD = "2026112601"
    NOW = 1795690000

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.key = self.root / "test-key.pem"
        self.pub = self.root / "app-catalog.pem"
        sp.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", self.key], check=True)
        sp.run(["openssl", "pkey", "-in", self.key, "-pubout", "-out", self.pub], check=True)

    def payload(self, channel="beta", build=BUILD):
        return {"format": 1, "channel": channel, "device": "frankel", "generation": int(build),
                "build": build, "min_os": build, "max_os": "2026120100",
                "issued": self.NOW, "expires": self.NOW + apps.LIFETIME}

    def test_signature_channel_expiry_and_generation(self):
        body = apps.sign_catalog(self.payload(), self.key)
        self.assertEqual(apps.verify_catalog(body, self.pub, "beta", self.NOW), self.payload())
        for channel, now, reason in (("stable", self.NOW, "identity"),
            ("beta", self.NOW + apps.LIFETIME, "expired"), ("beta", self.NOW - 301, "not yet valid")):
            with self.assertRaisesRegex(ValueError, reason):
                apps.verify_catalog(body, self.pub, channel, now)
        envelope = json.loads(body)
        payload = base64.b64decode(envelope["payload"]).replace(b"frankel", b"emu64x")
        with self.assertRaises(sp.CalledProcessError):
            apps.verify_catalog(apps.json_bytes(envelope | {"payload": apps.encoded(payload)}), self.pub, "beta")
        wrong_generation = apps.sign_catalog(self.payload() | {"generation": 1}, self.key)
        with self.assertRaisesRegex(ValueError, "version"):
            apps.verify_catalog(wrong_generation, self.pub, "beta")

    def test_reject_downgrade_or_changed_duplicate(self):
        old = apps.sign_catalog(self.payload(), self.key)
        apps.check_advance(old, "beta", self.root, old, self.BUILD)
        new = apps.sign_catalog(self.payload(build="2026112700"), self.key)
        apps.check_advance(old, "beta", self.root, new, "2026112700")
        with self.assertRaisesRegex(ValueError, "downgrade"):
            apps.check_advance(new, "beta", self.root, old, self.BUILD)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            apps.check_advance(old, "beta", self.root, b"edited", self.BUILD)

    def test_public_asset_failure_leaves_beta_unchanged(self):
        out = self.root / self.BUILD
        out.mkdir()
        entries = {}
        for name in apps.ASSETS:
            path = out / name
            path.write_bytes(name.encode())
            if name in apps.APPS:
                entries[name] = {"sha256": apps.digest(path)}
        expected = [{"name": p.name, "digest": "sha256:" + apps.digest(p)} for p in out.iterdir()]
        commit = "a" * 40
        channel = "desktop-apps-beta.json"
        old = apps.sign_catalog(self.payload(build="2026112500"), self.key)
        calls = []
        public = [old]

        def cli(argv, **_):
            if argv[0] == "aws":
                if "get-object" in argv:
                    Path(argv[argv.index("--key") + 2]).write_bytes(old)
                    return json.dumps({"ETag": '"old"'})
                self.assertIn("--if-match", argv)
                self.assertIn('"old"', argv)
                calls.append(argv[argv.index("--key") + 1])
                public[0] = (out / channel).read_bytes()
                return ""
            value = " ".join(argv)
            if "--paginate" in argv and "/tags" in value:
                return apps.tag(self.BUILD)
            if "--paginate" in argv and "/releases" in value:
                return "42"
            if "/releases/42" in value:
                return json.dumps({"draft": False, "assets": expected})
            if "/commits/" in value:
                return commit
            raise AssertionError(argv)

        class Response(io.BytesIO):
            def __init__(self, url, broken):
                super().__init__(b"corrupt" if broken else url.split("/")[-1].encode())
                self.url = url

        with patch.dict(os.environ, dict(BUILD_NUMBER=self.BUILD, SOURCE_COMMIT=commit, CHANNEL="beta",
                APP_SIGNED_ROOT=str(self.root), PUBLIC_TRUST=str(self.root), UNSIGNED_SUMS_SHA256="b"*64,
                OTA_BUCKET="test")), patch.object(apps, "verify_release", return_value={"apps": entries}), \
                patch.object(apps, "public_or_missing", side_effect=lambda _: public[0]), \
                patch.object(apps, "publicly", side_effect=lambda _: public[0]), \
                patch.object(apps.sp, "check_output", side_effect=cli):
            with patch.object(apps, "urlopen", side_effect=lambda url, **_: Response(url, True)):
                with self.assertRaisesRegex(ValueError, "download failed"):
                    apps.publish()
                self.assertEqual(calls, [])
                self.assertEqual(public[0], old)
            with patch.object(apps, "urlopen", side_effect=lambda url, **_: Response(url, False)):
                apps.publish()
                self.assertEqual(calls, [channel])
