"""Three complete child raw audits, with explicit synthetic external boundaries.

No Android, genuine APK cryptography, real image or real SDK runtime is claimed.
Every child parser/window/input/pixel/epoch/command validator executes unchanged.
"""
from pathlib import Path
import copy
import json
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tools"))
import conformance_clean_boot_raw_fixture as fixture
from test_phase1_conformance_clean_boot_raw_campaign import exact_pixel_decoder
import phase1_conformance_three_clean_boot_acceptance as audit
from phase1_conformance_common import canonical, canonical_sha256, file_ref, load


def write(path, value):
    path.write_bytes(canonical(value))


def reseal(directory):
    """Test-only hostile reseal; original raw audit must still detect defects."""
    report = load(directory / "report.json")
    runtime = directory / "runtime"
    for relative in ("commands.json", "runtime/commands.json"):
        path = directory / relative; trace = load(path)
        for row in trace:
            if row.get("evidence"):
                target = (runtime if relative.startswith("runtime/") else directory) / row["evidence"]
                row["output_sha256"] = file_ref(target)["sha256"]
                if "bytes" in row: row["bytes"] = target.stat().st_size
        write(path, trace)
    report["runtime_evidence"] = {str(path.relative_to(runtime)): file_ref(path)
        for path in runtime.rglob("*") if path.is_file()}
    report["evidence_files"] = {str(path.relative_to(directory)): file_ref(path)
        for path in directory.rglob("*") if path.is_file() and path.name != "report.json"}
    write(directory / "report.json", report)


class ThreeRawBootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.owner = unittest.TestCase()
        cls.original = fixture.Campaign(cls.owner)
        packet, original = cls.original.packet, cls.original.directory
        freeze = packet / "evidence/compile-input/source-freeze.json"
        files = load(freeze)["files"]
        for root in ("android/conformance", "android/desktop-sdk"):
            files[root + "/build.gradle.kts"] = file_ref(audit.ROOT / root / "build.gradle.kts")
            for path in (audit.ROOT / root / "src/main").rglob("*"):
                if path.is_file(): files[str(path.relative_to(audit.ROOT))] = file_ref(path)
        write(freeze, {"files": files})
        cls.original.report["client_sources"]["source_freeze"] = file_ref(freeze)
        product_manifest = load(original / "product-candidate-manifest.json")
        # This is ONLY an explicitly synthetic SDK identity. External Docker
        # admission is mocked; no bundled renderer/runtime bytes are claimed.
        product_manifest["emulator_runtime"] = {"version": "SYNTHETIC TEST ONLY",
            "sha256": "f" * 64, "files": {"emulator": {"kind": "file", "mode": 0o755, "sha256": "e" * 64}}}
        write(original / "product-candidate-manifest.json", product_manifest)
        manifest = load(original / "image-manifest.json")
        manifest["base_product_candidate"]["manifest_sha256"] = canonical_sha256(product_manifest)
        write(original / "image-manifest.json", manifest)
        trace = load(original / "commands.json")
        for row in trace:
            argv = row.get("argv", [])
            if argv[-1:] == ["verify"]:
                row["output"] = "Verifying fresh-guest Phase-1 conformance candidate…\n" + canonical(manifest).decode()
            elif argv[-1:] == ["/opt/wonad/product-candidate-manifest.json"]:
                row["output"] = canonical(product_manifest).decode()
        write(original / "commands.json", trace)
        cls.original.seal()
        cls.template_tmp = tempfile.TemporaryDirectory()
        cls.template = Path(cls.template_tmp.name) / "three-boots"; cls.template.mkdir()
        cls.contract = audit.input_contract(cls.original.report["image_id"], cls.original.product,
            cls.original.packet, cls.original.basis.receipt_sha)
        for index, name in enumerate(audit.BOOT_DIRS):
            cls.clone_child(original, cls.template / name, index)

    @classmethod
    def tearDownClass(cls):
        cls.template_tmp.cleanup(); cls.owner.doCleanups()

    @classmethod
    def clone_child(cls, source, destination, index):
        shutil.copytree(source, destination)
        report = load(destination / "report.json")
        substitutions = {str(source): str(destination), report["container_id"]: str(index + 1) * 64,
            report["container_run"]: str(index + 4) * 32, report["conformance_run"]: str(index + 7) * 32,
            report["boot_id"]: f"0000000{index + 1}-1234-1234-1234-000000000001"}
        offset = index * 1_000_000
        def rewrite(value, key=None):
            if isinstance(value, str):
                # Repeated hexadecimal fixture identities overlap deliberate
                # fake artifact hashes. Never rewrite a digest as a run token.
                if key and "sha256" in key: return value
                if re.fullmatch(r"[0-9a-f]{64}", value) and key not in {"container_id", "Id", "argv"}: return value
                marker = fixture.producer.runtime.STATUS_MARKER
                if value.startswith(marker):
                    return marker + json.dumps(rewrite(json.loads(value[len(marker):]))) + "\n"
                if value.lstrip().startswith(("{", "[")):
                    try: return json.dumps(rewrite(json.loads(value))) + "\n"
                    except json.JSONDecodeError: pass
                value = value.replace(str(source), str(destination))
                for old, new in substitutions.items():
                    if value in (old, old + "\n"): value = value.replace(old, new)
                    if key == "argv": value = value.replace(old + ":/state/", new + ":/state/")
                    for prefix in ("wonad-phase1-conformance-", "wonad-phase1-consent-", "phase1-recents-",
                                   "org.wonad.phase1-fresh-conformance=", "instrumentation-", "run="):
                        value = value.replace(prefix + old, prefix + new)
                    # The ordinary Docker name contains a bounded run prefix.
                    value = value.replace("wonad-phase1-conformance-" + old[:12],
                                          "wonad-phase1-conformance-" + new[:12])
                    value = value.replace("accepted " + old + " ", "accepted " + new + " ")
                return value
            if isinstance(value, list): return [rewrite(item, key) for item in value]
            if isinstance(value, dict): return {name: rewrite(item, name) for name, item in value.items()}
            if type(value) is int and key and key.endswith("monotonic_ns"): return value + offset
            return value
        for path in destination.rglob("*"):
            if not path.is_file() or path.suffix == ".png": continue
            if path.name in {"packet-receipt.json", "image-manifest.json", "product-candidate-manifest.json"}: continue
            if path.suffix == ".json": write(path, rewrite(load(path)))
            else: path.write_text(rewrite(path.read_text()))
        prelaunch = load(destination / "prelaunch-userdata.json")
        prelaunch["state"] = fixture.producer.fresh._directory_identity(destination / "emulator-state")
        prelaunch["tmp"] = fixture.producer.fresh._directory_identity(destination / "emulator-state/tmp")
        write(destination / "prelaunch-userdata.json", prelaunch)
        report = load(destination / "report.json"); report["prelaunch_state"] = prelaunch
        write(destination / "report.json", report); reseal(destination)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "three-boots"
        # Fresh fixture copies must themselves have actual new directory
        # identities; don't leave template inode summaries behind.
        self.directory.mkdir()
        for index, name in enumerate(audit.BOOT_DIRS):
            self.clone_child(self.template / name, self.directory / name, index)

    def child_audits(self):
        return patch.object(fixture.base.builder.packet_tool, "validate_receipt", return_value=None)

    def check(self):
        # Exact unchanged decoder outputs may be cached only for equal full
        # PNG bytes and equal region arguments, as in the reviewed child suite.
        with self.child_audits(), \
             patch.object(fixture.wrapper.api_acceptance, "candidate_offline", return_value=None), \
             patch.object(audit.child.raw_audit, "png_info", side_effect=exact_pixel_decoder):
            return audit.audit_children(self.directory, self.contract)

    def aggregate(self, records):
        write(self.directory / "contract-before.json", self.contract)
        attempts = []
        for record in records:
            name = record["directory"]
            row = {"directory": name, "status": "passed_original_child", "error": None,
                "report": record["report"], "started_monotonic_ns": record["started_monotonic_ns"],
                "ended_monotonic_ns": record["ended_monotonic_ns"]}
            attempts.append(row)
            write(self.directory / (name + "-started.json"), {key: value for key, value in
                {**row, "status": "started", "report": None}.items() if key != "ended_monotonic_ns"})
            write(self.directory / (name + "-ended.json"), row)
        write(self.directory / "attempts.json", attempts)
        report = {"schema": 1, "kind": audit.KIND, "scope": audit.SCOPE, "status": audit.STATUS,
            "boot_count": 3, "cycles_per_boot": 20, "connectors": 3, "runtime_qualified": False,
            "qualification_claimed": False, "separate_24h_campaign_required": True, "contract": self.contract,
            "children": records, "attempts": attempts, "attempt_journal": file_ref(self.directory / "attempts.json"),
            "started_monotonic_ns": 1, "ended_monotonic_ns": records[-1]["ended_monotonic_ns"] + 1}
        write(self.directory / "report.json", report)
        with self.child_audits(), \
             patch.object(fixture.wrapper.api_acceptance, "candidate_offline", return_value=None), \
             patch.object(audit.child.raw_audit, "png_info", side_effect=exact_pixel_decoder):
            return audit.audit_report(self.directory / "report.json", file_ref(self.directory / "report.json")["sha256"])

    def test_three_original_complete_raw_children_each_discharge_64_stages(self):
        records = self.check()
        self.assertEqual(len(records), 3)
        self.assertEqual([row["audit"] for row in records], [audit.CHILD_RESULT] * 3)
        self.assertEqual(len({row["identity"]["boot_id"] for row in records}), 3)
        self.assertEqual(self.aggregate(records), {"boot_count": 3, "cycles_per_boot": 20, "connectors": 3,
            "runtime_qualified": False, "qualification_claimed": False, "separate_24h_campaign_required": True})

    def test_real_child_auditor_rejects_skipped_cycle_after_hostile_summary_reseal(self):
        child = self.directory / "boot-02"; report = load(child / "report.json")
        del report["stages"][20]; write(child / "report.json", report); reseal(child)
        with self.assertRaisesRegex(ValueError, "Exactly 20|bracket exact cycle phase"):
            self.check()

    def test_real_child_auditor_rejects_phone_restart_even_when_raw_and_summary_resealed(self):
        child = self.directory / "boot-02"; report = load(child / "report.json")
        phase = report["stages"][3]; row = phase["processes"]["com.android.phone"]
        row["start_ticks"] += 1
        for key in ("before", "after"):
            path = child / "runtime" / row[key]
            text = path.read_text().replace(" 1004\n", " 1005\n"); path.write_text(text)
        write(child / "report.json", report); reseal(child)
        with self.assertRaisesRegex(ValueError, "epoch changed"):
            self.check()

    def test_raw_duplicate_boot_can_pass_each_child_but_not_the_aggregate(self):
        first, second = self.directory / "boot-01", self.directory / "boot-02"
        original = load(second / "report.json")["boot_id"]
        duplicate = load(first / "report.json")["boot_id"]
        for path in second.rglob("*"):
            if path.is_file() and path.suffix != ".png": path.write_text(path.read_text().replace(original, duplicate))
        reseal(second)
        with self.assertRaisesRegex(ValueError, "Duplicate actual boot_id"):
            self.check()


if __name__ == "__main__":
    unittest.main(verbosity=2)
