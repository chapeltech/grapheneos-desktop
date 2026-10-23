"""Two supplemental RED contracts for the frozen ec99 vendor runner.

Run beside test_run_frankel_vendor_lifecycle.py for the nine-test generation.
No Docker, checkout cleanup, real archive, or FICLONE operation is used.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock


TOOL = Path("/u/elric/tree/wonad/android/tools/run_frankel_vendor.py")
TOOL_SHA256 = "ec99cec9408f51b551ae59933a5d3f39ec77421bc646fde2c0229c0a463c0762"
assert hashlib.sha256(TOOL.read_bytes()).hexdigest() == TOOL_SHA256
SPEC = importlib.util.spec_from_file_location("frozen_vendor_supplement", TOOL)
vendor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vendor)


class SupplementalConfirmedGaps(unittest.TestCase):
    def test_source_topology_seals_stable_directory_identities(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "source"
            for relative in (".repo", "out", "vendor/adevtool"):
                (source / relative).mkdir(parents=True, exist_ok=True)
            topology = vendor.source_topology(
                types.SimpleNamespace(source=source), output_may_exist=False)
            rows = topology.get("directory_identities")
            self.assertIsInstance(rows, dict)
            self.assertEqual({"source", "repo_metadata", "out", "adevtool"}, set(rows))
            for key, path in {
                    "source": source,
                    "repo_metadata": source / ".repo",
                    "out": source / "out",
                    "adevtool": source / "vendor/adevtool"}.items():
                actual = path.lstat()
                self.assertEqual(
                    {"device": actual.st_dev, "inode": actual.st_ino,
                     "uid": actual.st_uid, "gid": actual.st_gid,
                     "mode": actual.st_mode & 0o7777},
                    {name: rows[key][name]
                     for name in ("device", "inode", "uid", "gid", "mode")})

    def test_reflink_evidence_must_not_claim_a_future_adevtool_recheck(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            cache = root / "cache"
            cache.mkdir()
            archive = cache / "factory.zip"
            archive.write_bytes(b"small synthetic archive")
            config = types.SimpleNamespace(
                cache=cache, archive_name=archive.name,
                archive_bytes=archive.stat().st_size,
                archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
                work=root / "work")

            def synthetic_clone(destination, operation, source):
                self.assertEqual(vendor.FICLONE, operation)
                os.lseek(source, 0, os.SEEK_SET)
                os.write(destination, os.read(source, config.archive_bytes))

            with mock.patch.object(vendor, "validate_cache", return_value={}):
                evidence = vendor.prepare_reflink(config, ioctl_fn=synthetic_clone)
            row = evidence["archive"]
            self.assertNotIn("sha256_rechecked_by_adevtool", row)
            self.assertEqual(config.archive_sha256,
                             row["sha256_from_authenticated_receipt"])
            self.assertTrue(row["adevtool_consumption_and_recheck_pending"])


if __name__ == "__main__":
    unittest.main()
