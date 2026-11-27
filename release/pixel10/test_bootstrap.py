import base64
import ctypes
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import hosted_bootstrap as bootstrap
import hosted_keys as keys


class Bootstrap(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lib = bootstrap.sodium()
        public, self.private = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
        self.assertEqual(self.lib.crypto_box_keypair(public, self.private), 0)
        self.public = public.raw

    def opened(self, value):
        sealed = base64.b64decode(value, validate=True)
        plaintext = ctypes.create_string_buffer(len(sealed) - bootstrap.SEAL_BYTES)
        decrypt = self.lib.crypto_box_seal_open
        decrypt.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulonglong,
                            ctypes.c_char_p, ctypes.c_void_p)
        self.assertEqual(decrypt(plaintext, sealed, len(sealed), self.public, self.private), 0)
        return plaintext.raw.decode("ascii")

    def test_only_sealed_chunks_leave_the_runner(self):
        for kind, files in keys.FILES.items():
            (self.root / kind).mkdir()
            for name in files:
                (self.root / kind / name).write_bytes(("private test " + name).encode())
        sealed = bootstrap.sealed_slots(self.root, self.public)
        self.assertEqual(set(sealed), bootstrap.SLOTS)
        for kind in keys.FILES:
            expected = keys.pack(kind, self.root / kind)
            self.assertEqual([self.opened(sealed[name]) for name in keys.secret_names(kind)], expected)

    def test_install_requires_the_reviewed_run_and_never_overwrites_keys(self):
        run, commit = "123456", "a" * 40
        trust = self.root / "trust"
        trust.mkdir()
        for name in bootstrap.PUBLIC:
            (trust / name).write_bytes(b"public test fixture")
        record = {"repo": bootstrap.security.REPO, "environment": bootstrap.security.ENVIRONMENT,
                  "commit": commit, "run": run, "attempt": "1", "key_id": "42",
                  "recipient_sha256": hashlib.sha256(self.public).hexdigest(),
                  "encrypted": {name: bootstrap.seal(self.lib, self.public, b"fixture")
                                for name in bootstrap.SLOTS}}
        (self.root / "sealed.json").write_text(json.dumps(record))
        receipt = {"event": "workflow_dispatch", "conclusion": "success", "run_attempt": 1,
                   "head_branch": "release/pixel10", "head_sha": commit,
                   "head_repository": {"full_name": bootstrap.security.REPO}, "path": bootstrap.WORKFLOW}
        recipient = {"key_id": "42", "key": base64.b64encode(self.public).decode("ascii")}
        installed = {}

        def github(path, body=None):
            if path.endswith("/jobs"):
                return {"jobs": [{"name": "bootstrap-keys", "conclusion": "success"}]}
            if path.endswith(f"/actions/runs/{run}"):
                return receipt
            if path.endswith("/public-key"):
                return recipient
            if path.endswith("?per_page=100"):
                return {"secrets": [{"name": name} for name in installed]}
            self.assertIsNotNone(body)
            name = path.split("/")[-1]
            self.assertNotIn(name, installed)
            self.assertEqual(body["key_id"], "42")
            installed[name] = self.opened(body["encrypted_value"])

        with patch.object(bootstrap, "gh_api", side_effect=github):
            receipt["head_branch"] = "dev/unreviewed"
            with self.assertRaisesRegex(ValueError, "approved release branch"):
                bootstrap.install(self.root, run, commit)
            receipt["head_branch"] = "release/pixel10"
            recipient["key_id"] = "99"
            with self.assertRaisesRegex(ValueError, "environment encryption key"):
                bootstrap.install(self.root, run, commit)
            recipient["key_id"] = "42"
            self.assertEqual(installed, {})
            bootstrap.install(self.root, run, commit)
            self.assertEqual(installed, dict.fromkeys(bootstrap.SLOTS, "fixture"))
            with self.assertRaisesRegex(ValueError, "do not rerun or overwrite"):
                bootstrap.install(self.root, run, commit)
