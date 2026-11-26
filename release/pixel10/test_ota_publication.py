import base64
import json
import unittest
from unittest.mock import patch

import ota_publication as pointers


class GithubPointers(unittest.TestCase):
    def test_validate_only_known_pointer_paths(self):
        for name in ("../README.md", "frankel-ota_update-2026112601.zip", "frankel-testing"):
            with self.assertRaises(ValueError):
                pointers.pointer(name)

    def test_update_uses_exact_observed_blob_sha(self):
        value = b"2026112603 1795690000 frankel beta\n"
        sha = "a" * 40
        public = {"sha": sha, "content": base64.b64encode(value).decode(),
                  "size": len(value), "encoding": "base64", "type": "file"}
        with patch.object(pointers, "api", return_value=public) as api:
            self.assertEqual(pointers.read("frankel-beta"), (value, sha))
            api.assert_called_once_with(pointers.pointer("frankel-beta") + "?ref=ota")
            pointers.write("frankel-beta", value, sha)
            url, data = api.call_args.args
            self.assertEqual(url, pointers.pointer("frankel-beta"))
            self.assertEqual(json.loads(data)["sha"], sha)
            self.assertEqual(json.loads(data)["branch"], "ota")
