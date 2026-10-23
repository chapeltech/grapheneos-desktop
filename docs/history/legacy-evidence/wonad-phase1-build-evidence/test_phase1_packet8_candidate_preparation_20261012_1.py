"""Host-only checks for packet8-bound native5/derived7/wrong8 recipes.

Never execute a resolved native recipe: shell probes mutate a single pin back
to PENDING in memory so every probe exits before its lock/filesystem/Docker work.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import subprocess
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = Path("/u/elric/tree/wonad")
NATIVE4 = HERE / "run-phase1-native-candidate-custom7-5-4.sh"
NATIVE5 = HERE / "run-phase1-native-candidate-custom7-5-5.sh"
DERIVED6 = HERE / "run-phase1-conformance-candidate-custom7-5-6.sh"
DERIVED7 = HERE / "run-phase1-conformance-candidate-custom7-5-7.sh"
WRONG7 = HERE / "run-phase1-wrong-signer-bundle7-20261011-1.py"
WRONG8 = HERE / "run-phase1-wrong-signer-bundle8-20261012-1.py"
BASELINE_SHA = "b97a89f6f05381c2f2836271298d1b9b578d085760c76bd7655786121ec36a25"
COMPARISON_SHA = "fae0aee21d024638d67e99e619712b5d6b8e8a16c6f6b8d902dbc1c19c7f244e"
PACKET_PINS = {
    "packet_sha": "b30fbb787eb8f39cb573db076a2ac0954cf98f61d375b49d465cc42b355ef3ee",
    "packet_wonad_sha": "7494132416df3b4957ca944bdf5657be3d6e1df2a6eca74833462702d4d1e2ac",
    "packet_update_sha": "ebc701b504bb9abc696b5817ea57e649da8b3502cbaf79d7fe2dc3b6e14e1987",
    "packet_conformance_update_sha": "444f1fab34059c0f0d4c32033f86c3b38ac529727f95ba422d323dcbd5bc543a",
    "packet_wonad_cert_sha": "65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3",
    "packet_platform_cert_sha": "9837de028f460c35cc8d3fa45f14eecce30f6fbfe4b93d399aef1acb80c20d14",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="strict")


def constants(path: Path) -> dict[str, str]:
    return dict(re.findall(r"^readonly ([a-z0-9_]+)=(.*)$", read(path), flags=re.MULTILINE))


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Packet8CandidatePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native4 = read(NATIVE4)
        cls.native5 = read(NATIVE5)
        cls.derived6 = read(DERIVED6)
        cls.derived7 = read(DERIVED7)
        cls.wrong7 = load(WRONG7, "phase1_wrong7_reference")
        cls.wrong8 = load(WRONG8, "phase1_wrong8_pending")

    def test_shell_recipes_are_syntactically_valid(self):
        for path in (NATIVE5, DERIVED7):
            result = subprocess.run(["/bin/bash", "-n", str(path)], text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)

    def test_native5_is_exact_native4_recipe_with_only_generation_and_pending_packet(self):
        restored = self.native5
        replacements = {
            "phase1-emulator-client-packet-20261012-8": "phase1-emulator-client-packet-20261011-7",
            "readonly packet_sha=" + PACKET_PINS["packet_sha"]:
                "readonly packet_sha=5d5737ebe26048152fccfb4881cd89fb4b583ca2df0cfc84fbe8d023799cc459",
            "readonly packet_wonad_sha=" + PACKET_PINS["packet_wonad_sha"]:
                "readonly packet_wonad_sha=7494132416df3b4957ca944bdf5657be3d6e1df2a6eca74833462702d4d1e2ac",
            "readonly packet_update_sha=" + PACKET_PINS["packet_update_sha"]:
                "readonly packet_update_sha=1eef12a24e976bf4711c8c2e2872096436f28621c6ebe07c0151dd37aa29e177",
            "readonly packet_conformance_update_sha=" + PACKET_PINS["packet_conformance_update_sha"]:
                "readonly packet_conformance_update_sha=2febd46ac4870fafe053798258a450ef328f39887d680cbeeab4d0bc033b2293",
            "readonly packet_wonad_cert_sha=" + PACKET_PINS["packet_wonad_cert_sha"]:
                "readonly packet_wonad_cert_sha=65e326ada8f623cd6e1852d6fefba8262f445bcd5949966e10361c6d770c70a3",
            "readonly packet_platform_cert_sha=" + PACKET_PINS["packet_platform_cert_sha"]:
                "readonly packet_platform_cert_sha=9837de028f460c35cc8d3fa45f14eecce30f6fbfe4b93d399aef1acb80c20d14",
            "phase1-native-candidate-custom7-5-5": "phase1-native-candidate-custom7-5-4",
            "wonad:native-v3-candidate-phase1-custom7-5-5":
                "wonad:native-v3-candidate-phase1-custom7-5-4",
            "NOT READY: packet8 publication pins remain PENDING":
                "packet7 publication pins are unresolved; this prepared driver cannot run",
        }
        for current, previous in replacements.items():
            self.assertIn(current, restored)
            restored = restored.replace(current, previous)
        self.assertEqual(self.native4, restored)

    def test_native5_preserves_exact_source_build_and_resource_guards(self):
        old, new = constants(NATIVE4), constants(NATIVE5)
        for name in ("repo", "python", "python_target", "python_sha", "builder", "builder_sha",
                     "x86", "x86_sha", "packet_tool", "packet_tool_sha", "product",
                     "baseline", "custom", "custom_sha", "comparison", "base"):
            self.assertEqual(old[name], new[name], name)
        for statement in (
            "(( mem_kib >= 12 * 1024 * 1024 ))",
            "(( u_free >= 16 * gib ))", "(( tmp_free >= 4 * gib ))",
            "(( docker_free >= 16 * gib ))", "--phase1-build-evidence",
            '--phase1-comparison "$comparison"', '--phase1-baseline-receipt "$baseline"',
            '--phase1-custom-receipt "$custom"', '--phase1-client-packet "$packet"',
        ):
            self.assertIn(statement, self.native5)
        for path, variable in (
            ("receipt.json", "packet_sha"), ("wonad.apk", "packet_wonad_sha"),
            ("version-update/preparation-receipt.json", "packet_update_sha"),
            ("conformance-version-update/preparation-receipt.json",
             "packet_conformance_update_sha"),
            ("evidence/certificates/wonad.x509.pem", "packet_wonad_cert_sha"),
            ("evidence/certificates/platform.x509.pem", "packet_platform_cert_sha"),
        ):
            self.assertEqual(2, self.native5.count(f'exact_sha "$packet/{path}" "${variable}"'))

    def test_native5_fails_before_lock_or_packet_access_while_pending(self):
        for name, digest in PACKET_PINS.items():
            pending = self.native5.replace(f"readonly {name}={digest}", f"readonly {name}=PENDING")
            self.assertNotEqual(pending, self.native5)
            result = subprocess.run(["/bin/bash", "-s", "--", BASELINE_SHA, COMPARISON_SHA],
                                    input=pending, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.subTest(pin=name):
                self.assertEqual(78, result.returncode)
                self.assertIn("packet8 publication pins remain PENDING", result.stderr)
                self.assertNotIn("preflight", result.stdout)

    def test_derived7_preserves_derived6_recipe_except_pending_inputs_and_generation(self):
        old, new = constants(DERIVED6), constants(DERIVED7)
        for name in ("repo", "python", "python_target", "python_sha", "builder", "builder_sha",
                     "native_builder", "native_builder_sha", "packet_tool", "packet_tool_sha",
                     "smoke_source", "smoke_source_sha", "common_source", "common_source_sha",
                     "guest_source", "guest_source_sha", "api_auditor", "api_auditor_sha",
                     "product"):
            self.assertEqual(old[name], new[name], name)
        self.assertEqual("PENDING", new["native_image"])
        self.assertEqual("$repo/android/out/phase1-emulator-client-packet-20261012-8", new["packet"])
        self.assertEqual("$repo/android/out/phase1-native-candidate-custom7-5-5", new["native_output"])
        self.assertEqual("wonad:native-v3-candidate-phase1-custom7-5-5", new["native_tag"])
        self.assertEqual("$repo/android/out/phase1-conformance-candidate-custom7-5-7", new["output"])
        self.assertEqual("wonad:phase1-conformance-candidate-custom7-5-7", new["tag"])
        for name in ("packet_sha", "packet_wonad_sha", "packet_update_sha",
                     "packet_conformance_update_sha", "packet_wonad_cert_sha",
                     "packet_platform_cert_sha"):
            self.assertEqual(PACKET_PINS[name], new[name])
        for source in ("smoke_source", "common_source", "guest_source", "api_auditor"):
            self.assertEqual(2, self.derived7.count(f'exact_sha "${source}" "${source}_sha"'))

    def test_full_derived_recipe_reverses_to_exact_predecessor_without_guard_changes(self):
        old, new = constants(DERIVED6), constants(DERIVED7)
        restored = self.derived7
        restored = restored.replace(
            "# Fill this only from the terminal, independently audited native5 publication.",
            "# This exact immutable ID may be filled only from the terminal native4\n"
            "# publication.  It deliberately remains unresolved in this preparation.")
        for name in ("native_image", "packet", *PACKET_PINS, "native_output", "native_tag", "output", "tag"):
            current = f"readonly {name}={new[name]}"
            self.assertIn(current, restored)
            restored = restored.replace(current, f"readonly {name}={old[name]}")
        for current, previous in (
            ("native5 immutable image ID", "native4 immutable image ID"),
            ("authenticated native5 image is authorized for derived7", "authenticated native4 image is authorized for derived6"),
            ("NOT READY: packet8/bundled-host source pins remain PENDING or invalid",
             "reviewed packet7/bundled-host source pins are unresolved; this prepared driver cannot run"),
        ):
            self.assertIn(current, restored)
            restored = restored.replace(current, previous)
        self.assertEqual(self.derived6, restored)

    def test_derived7_pending_and_wrong_native_guards_precede_other_work(self):
        image = "sha256:" + "a" * 64
        result = subprocess.run(["/bin/bash", str(DERIVED7), image], text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(78, result.returncode)
        self.assertIn("native5 immutable image ID remains PENDING", result.stderr)
        bound = self.derived7.replace("readonly native_image=PENDING",
                                     "readonly native_image=" + image)
        result = subprocess.run(["/bin/bash", "-s", "--", "sha256:" + "b" * 64],
                                input=bound, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(65, result.returncode)
        self.assertIn("only the authenticated native5 image", result.stderr)
        pending = bound.replace("readonly packet_sha=" + PACKET_PINS["packet_sha"],
                                "readonly packet_sha=PENDING")
        result = subprocess.run(["/bin/bash", "-s", "--", image], input=pending, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(78, result.returncode)
        self.assertIn("packet8/bundled-host source pins", result.stderr)

    def test_derived_builder_still_bundles_exact_four_core_host_sources(self):
        builder = read(ROOT / "android/container/build-phase1-conformance-candidate.py")
        source_block = builder.split("SOURCE_FILES = {", 1)[1].split("}\n", 1)[0]
        self.assertEqual({"conformance_smoke.py", "common.py", "driver.py", "acceptance.py"},
                         set(re.findall(r'^\s*"([^"]+)":', source_block,
                                        flags=re.MULTILINE)))
        self.assertNotIn("phase1_conformance_recents", self.derived7)

    def test_wrong8_is_unresolved_and_cannot_touch_partial_packet_or_exec(self):
        self.assertTrue(self.wrong8.publication_pins_resolved())
        with mock.patch.object(self.wrong8, "PACKET_RECEIPT_SHA256", "PENDING"), \
                mock.patch.object(self.wrong8, "exact_file") as exact, \
                mock.patch.object(self.wrong8.os, "execve") as execute:
            with self.assertRaisesRegex(ValueError, "remain PENDING"):
                self.wrong8.preflight()
            with self.assertRaisesRegex(ValueError, "remain PENDING"):
                self.wrong8.main(["--execute-after-root-authorization"])
        exact.assert_not_called()
        execute.assert_not_called()

    def test_actual_bound_public_inputs_match_packet8_without_conversion(self):
        with mock.patch.object(self.wrong8.os, "execve") as execute:
            value = self.wrong8.preflight()
        execute.assert_not_called()
        self.assertEqual(PACKET_PINS["packet_sha"], value["packet_receipt_sha256"])
        self.assertEqual("prepared_not_executed", value["status"])
        self.assertFalse(value["private_keys_consumed"])
        self.assertFalse(self.wrong8.OUTPUT.exists())

    def test_wrong8_rejects_missing_duplicate_alias_or_nonpositive_public_records(self):
        valid = {name: ("a" * 64, 1) for name in self.wrong8.EXPECTED_FILE_NAMES}
        with mock.patch.object(self.wrong8, "PACKET_RECEIPT_SHA256", "b" * 64), \
                mock.patch.object(self.wrong8, "EXPECTED_FILES", valid):
            self.assertTrue(self.wrong8.publication_pins_resolved())
            for mutation in (
                {name: row for name, row in valid.items() if name != "wonad.apk"},
                {**valid, "foreign.apk": ("a" * 64, 1)},
                {**valid, "wonad.apk": ("a" * 64, True)},
                {**valid, "wonad.apk": ("PENDING", 1)},
                {**valid, "wonad.apk": ("a" * 64, 0)},
            ):
                with self.subTest(mutation=set(mutation)):
                    with mock.patch.object(self.wrong8, "EXPECTED_FILES", mutation):
                        self.assertFalse(self.wrong8.publication_pins_resolved())

    def test_wrong8_delegates_only_to_reviewed_public_signature_pair_converter(self):
        self.assertEqual(self.wrong7.CONVERTER_SHA256, self.wrong8.CONVERTER_SHA256)
        self.assertEqual(self.wrong7.AUDITOR_SHA256, self.wrong8.AUDITOR_SHA256)
        self.assertEqual(self.wrong7.PACKET_TOOL_SHA256, self.wrong8.PACKET_TOOL_SHA256)
        command = self.wrong8.command()
        self.assertEqual([str(self.wrong8.PYTHON), "-B", str(self.wrong8.CONVERTER)], command[:3])
        self.assertNotIn("--keystore", command)
        self.assertNotIn("--signer", command)
        self.assertNotIn("--private-key", command)
        converter = read(self.wrong8.CONVERTER)
        self.assertIn("payload == members(wrong_raw)", converter)
        self.assertIn("source_packet_ephemeral_key_removed_public_material_only_no_private_key_consumed",
                      converter)
        self.assertIn("packet_tool.validate_receipt", converter)

    def test_fresh_outputs_and_old_generations_are_separate(self):
        self.assertNotEqual(constants(NATIVE4)["output"], constants(NATIVE5)["output"])
        self.assertNotEqual(constants(DERIVED6)["output"], constants(DERIVED7)["output"])
        self.assertNotEqual(self.wrong7.OUTPUT, self.wrong8.OUTPUT)
        self.assertIn("phase1-native-candidate-custom7-5-4", self.native4)
        self.assertIn("phase1-conformance-candidate-custom7-5-6", self.derived6)
        self.assertIn("phase1-wrong-signer-bundle-20261011-7", str(self.wrong7.OUTPUT))


if __name__ == "__main__":
    unittest.main()
