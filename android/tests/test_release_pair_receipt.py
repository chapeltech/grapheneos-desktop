import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ANDROID = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_pair_receipt", ANDROID / "tools/release_pair_receipt.py")
pair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pair)

OLD = "2026101000"
NEW = "2026101001"
OLD_TIME = 1791633600
NEW_TIME = 1791633600
SIGNER = "a" * 64


def post_build(number):
    return f"Wonad/frankel/frankel:17/FIXTURE/{number}:user/release-keys"


def endpoint(number, timestamp, source, stage, updater):
    return {
        "build": {
            "number": number,
            "post_build": post_build(number),
            "timestamp": timestamp,
            "datetime_utc": "2026-10-10T12:00:00+00:00",
        },
        "target": {
            "device": "Pixel 10", "product": "frankel", "abi": "arm64-v8a",
            "variant": "user", "lunch_target": "frankel-cur-user",
        },
        "source": source,
        "grapheneos_lock": {"release": "2026100600", "sha256": "b" * 64, "size": 1},
        "wonad_stage": stage,
        "updater_stage": updater,
        "phase1_provenance": {
            "selected_target": "production",
            "source_record": {"sha256": "6" * 64},
            "client_record": {"sha256": "7" * 64},
        },
        "apk_signer_sha256": SIGNER,
    }


class PairReceipt(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "grapheneos"
        (self.source / ".repo").mkdir(parents=True)
        script = self.source / "script"
        script.mkdir()
        generator = script / "generate-delta.sh"
        generator.write_text("#!/bin/bash\n# official fixture\n")
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                      "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")):
            subprocess.run(["git", "-C", str(script), *args], check=True,
                           capture_output=True)

        self.sources = {
            "manifest": {"commit": "1" * 40, "url": "https://example.invalid/manifest"},
            "frameworks_base": {"commit": "2" * 40, "url": "https://example.invalid/base"},
            "launcher3": {"commit": "3" * 40, "url": "https://example.invalid/launcher"},
            "updater": {"commit": "4" * 40, "url": "https://example.invalid/updater"},
            "emulator_goldfish": {"commit": "0" * 40,
                                  "url": "https://example.invalid/goldfish"},
        }
        self.stage = {
            "path": "external/wonad/.wonad-stage.json", "sha256": "5" * 64,
            "size": 100, "schema": 4, "frameworks_revision": "2" * 40,
            "launcher3_revision": "3" * 40, "signer_sha256": SIGNER,
            "emulator_goldfish_revision": "0" * 40,
            "signer_certificate": {"path": "WonadReleaseCertificate.der",
                                   "sha256": SIGNER, "size": 512},
            "files": {"WonadReleaseCertificate.der": SIGNER},
            "patches": {"frameworks_base": [{"name": "one.patch", "sha256": "6" * 64}],
                        "launcher3": [{"name": "two.patch", "sha256": "7" * 64}],
                        "emulator_goldfish": [{"name": "three.patch", "sha256": "0" * 64}]},
            "platform_targets": {"frameworks_base": {"a": "8" * 64},
                                 "launcher3": {"b": "9" * 64},
                                 "emulator_goldfish": {"c": "0" * 64}},
            "tools": {"android/platform/release-build.sh": "c" * 64},
        }
        self.updater = {
            "path": ".wonad-updater-stage.json", "sha256": "d" * 64, "size": 100,
            "schema": 1, "updater_revision": "4" * 40,
            "update_url": "https://updates.example.invalid/",
            "baseline_sha256": "e" * 64, "configured_sha256": "f" * 64,
            "configured_resource": {"path": "packages/apps/Updater/res/values/config.xml",
                                    "sha256": "f" * 64, "size": 10},
        }
        self.old = endpoint(OLD, OLD_TIME, self.sources, self.stage, self.updater)
        self.new = endpoint(NEW, NEW_TIME, self.sources, self.stage, self.updater)
        self.state = {"source": self.sources, "wonad_stage": self.stage,
                      "updater_stage": self.updater}
        self.paths = pair.endpoint_paths(self.source, OLD, NEW)
        self.paths["predecessor"].parent.mkdir(parents=True)
        self.paths["successor"].parent.mkdir(parents=True)
        self.paths["predecessor"].write_text(json.dumps(self.old, sort_keys=True))
        self.paths["successor"].write_text(json.dumps(self.new, sort_keys=True))
        self.write_delta()

    def write_delta(self, **changes):
        metadata = {
            "ota-type": "AB",
            "ota-required-cache": "0",
            "pre-device": "frankel",
            "pre-build": post_build(OLD),
            "pre-build-incremental": OLD,
            "post-build": post_build(NEW),
            "post-build-incremental": NEW,
            "post-timestamp": str(NEW_TIME),
        }
        metadata.update(changes)
        self.paths["incremental"].parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(self.paths["incremental"], "w") as archive:
            archive.writestr(pair.METADATA_NAME,
                             "".join(f"{key}={value}\n" for key, value in metadata.items()))
            archive.writestr("payload.bin", b"signed incremental payload")
            archive.writestr("payload_properties.txt", b"FILE_HASH=fixture\n")

    def endpoint_value(self, path):
        return self.old if Path(path) == self.paths["predecessor"] else self.new

    def contexts(self):
        generator = self.source / "script/generate-delta.sh"
        locked = {
            "name": "script/generate-delta.sh",
            "repository_commit": subprocess.check_output(
                ["git", "-C", str(generator.parent), "rev-parse", "HEAD"],
                text=True).strip(),
            **pair.file_reference(generator),
        }
        return (
            patch.object(pair.release_receipt, "verify_release_source", return_value=self.state),
            patch.object(pair.release_receipt, "dedicated_source", return_value=self.source),
            patch.object(pair.release_receipt, "verify_receipt", side_effect=self.endpoint_value),
            patch.object(pair, "locked_delta_generator", return_value=locked),
        )

    def create(self):
        one, two, three, four = self.contexts()
        with one, two, three, four:
            return pair.create_pair_receipt(self.source, OLD, NEW)

    def verify(self):
        one, two, three, four = self.contexts()
        with one, two, three, four:
            return pair.verify_pair_receipt(self.paths["pair"])

    def test_create_and_verify_binds_both_complete_lineages_and_official_script(self):
        output = self.create()
        self.assertEqual(self.paths["pair"], output)
        value = json.loads(output.read_text())
        self.assertEqual(pair.KIND, value["kind"])
        self.assertEqual(OLD, value["predecessor"]["number"])
        self.assertEqual(NEW, value["successor"]["number"])
        self.assertEqual(self.sources, value["successor"]["source"])
        self.assertEqual(self.stage, value["successor"]["wonad_stage"])
        self.assertEqual("script/generate-delta.sh",
                         value["official_delta_generator"]["name"])
        self.assertRegex(value["official_delta_generator"]["repository_commit"],
                         r"^[0-9a-f]{40}$")
        serialized = output.read_text().lower()
        for secret_marker in (".pk8", "private key", "id_ed25519\""):
            self.assertNotIn(secret_marker, serialized)
        verified = self.verify()
        self.assertEqual(self.new, verified["successor"])

    def test_project_lock_pins_the_exact_stable_grapheneos_delta_script(self):
        locked = pair.locked_delta_generator()
        self.assertEqual({
            "name": "script/generate-delta.sh",
            "repository_commit": "09d651841b55e42b9cee7392f0ce29ebda8c8fb5",
            "sha256": "2e0f80721588ff8f45b298f8242e8af658297c1916ff276b9456c1b4e957ef63",
            "size": 1026,
        }, locked)

    def test_numbers_are_exact_monotonic_and_rejected_before_source_access(self):
        invalid = (("202610100", NEW), (OLD, "20261010001"),
                   (NEW, OLD), (OLD, OLD), ("2026-10-10", NEW))
        for predecessor, successor in invalid:
            with self.subTest(predecessor=predecessor, successor=successor), \
                    patch.object(pair.release_receipt, "verify_release_source",
                                 side_effect=AssertionError("source accessed")), \
                    self.assertRaises(pair.PairReceiptError):
                pair.verify_endpoints(self.source, predecessor, successor)

    def test_existing_pair_receipt_is_never_overwritten(self):
        output = self.create()
        original = output.read_bytes()
        with self.assertRaisesRegex(pair.PairReceiptError, "refusing overwrite"):
            self.create()
        self.assertEqual(original, output.read_bytes())

    def test_metadata_must_name_exact_predecessor_and_successor_without_downgrade(self):
        for changes in ({"pre-build-incremental": "2026100999"},
                        {"post-build": post_build("2026101999")},
                        {"pre-device": "shiba"}, {"ota-downgrade": "yes"},
                        {"spl-downgrade": "yes"}):
            with self.subTest(changes=changes):
                self.write_delta(**changes)
                with self.assertRaisesRegex(pair.PairReceiptError,
                                            "metadata|downgrade"):
                    self.create()
                self.paths["pair"].unlink(missing_ok=True)

    def test_current_successor_source_and_endpoint_signer_channel_are_mandatory(self):
        bad_state = dict(self.state, source={"manifest": {"commit": "0" * 40}})
        one, two, three, four = self.contexts()
        with patch.object(pair.release_receipt, "verify_release_source", return_value=bad_state), \
                two, three, four, \
                self.assertRaisesRegex(pair.PairReceiptError, "source/stage lineage"):
            pair.verify_endpoints(self.source, OLD, NEW)

        self.new["apk_signer_sha256"] = "0" * 64
        with self.assertRaisesRegex(pair.PairReceiptError, "signer lineage"):
            self.create()

    def test_tampered_delta_endpoint_or_duplicate_pair_json_fails_closed(self):
        self.create()
        original_delta = self.paths["incremental"].read_bytes()
        self.paths["incremental"].write_bytes(original_delta + b"tamper")
        with self.assertRaisesRegex(pair.PairReceiptError, "OTA identity"):
            self.verify()
        self.paths["incremental"].write_bytes(original_delta)

        self.paths["predecessor"].write_text("changed endpoint receipt")
        with self.assertRaisesRegex(pair.PairReceiptError, "Predecessor receipt identity"):
            self.verify()

        # Authentication of this file is performed by verify_release_pair; the
        # structural verifier must still reject ambiguous duplicate fields.
        raw = self.paths["pair"].read_text().replace(
            '  "schema": 1,', '  "schema": 1,\n  "schema": 1,', 1)
        self.paths["pair"].write_text(raw)
        with self.assertRaisesRegex(pair.PairReceiptError, "Duplicate JSON field"):
            self.verify()

    def test_offline_pair_layout_never_follows_endpoint_directory_symlinks(self):
        self.create()
        build_directory = self.paths["predecessor"].parents[1]
        held = build_directory.with_name(build_directory.name + "-held")
        build_directory.rename(held)
        build_directory.symlink_to(held, target_is_directory=True)
        with self.assertRaisesRegex(pair.PairReceiptError, "layout contains a symlink"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
