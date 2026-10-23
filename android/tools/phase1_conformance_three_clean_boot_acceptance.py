#!/usr/bin/env python3
"""Independently reopen exactly three original policy-free 20-cycle boots.

This bounded aggregate is not the separate 24-hour campaign, full API gate,
product-policy qualification or overall Phase-1 runtime qualification.
"""
from pathlib import Path
import re
import sys

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parents[1]
sys.path.insert(0, str(TOOLS))
import phase1_conformance_clean_boot as child
import phase1_conformance_acceptance as fresh_audit
import phase1_conformance_recents_guest_acceptance as wrapper_audit
import run_phase1_conformance_recents_guest as wrapper
from phase1_conformance_common import (BOOT_ID, IMAGE_ID, RUN, SHA256, canonical,
    canonical_sha256, file_ref, load)

KIND = "phase1_policy_free_three_clean_boots_v1"
SCOPE = "three_distinct_fresh_conformance_only_guests_twenty_populated_connector_cycles_each"
STATUS = "passed_three_clean_boots_not_runtime_qualified"
CHILD_RESULT = {"cycles": 20, "connectors": 3, "runtime_qualified": False, "qualification_claimed": False}
BOOT_DIRS = tuple(f"boot-{number:02d}" for number in range(1, 4))


def require(value, message):
    if not value:
        raise ValueError(message)


def source_contract():
    """Pin the reused child and its actual host validators, not just summaries."""
    modules = {"child_producer": child, "child_auditor": child.acceptance,
        "runtime_status": child.runtime, "fresh_guest": child.fresh,
        "stream_mechanics": child.mechanics, "raw_window_pixel_audit": child.raw_audit,
        "fresh_auditor": fresh_audit, "outer_trace_auditor": wrapper_audit,
        "guest_wrapper": wrapper, "packet_validator": child.fresh.packet_tool,
        "candidate_builder": child.fresh.candidate_builder}
    comparison = child.fresh.candidate_builder.native.x86_comparison
    modules.update(x86_comparison=comparison, provenance=comparison.provenance,
        locality=comparison.locality, partition_capacity=comparison.partition_capacity,
        stage_contract=comparison.stage_contract)
    paths = {name: Path(module.__file__).resolve(strict=True) for name, module in modules.items()}
    paths.update(aggregate_producer=TOOLS / "phase1_conformance_three_clean_boot.py",
        aggregate_auditor=Path(__file__).resolve(), common=TOOLS / "phase1_conformance_common.py",
        image_builder=ROOT / "android/container/build.py",
        native_candidate_builder=ROOT / "android/container/build-native-candidate.py",
        modem_assets=ROOT / "android/demo/modem_assets.py",
        emulator_identity=ROOT / "android/demo/emulator_identity.py",
        control=ROOT / "android/demo/control.py", session=ROOT / "android/demo/session.py",
        entrypoint=ROOT / "android/container/entrypoint.py")
    return {role: {"path": str(path.resolve(strict=True)), **file_ref(path.resolve(strict=True))}
            for role, path in paths.items()}


def compiled_sources(packet):
    freeze_path = packet / "evidence/compile-input/source-freeze.json"
    freeze = load(freeze_path)
    paths = [ROOT / "android/conformance/build.gradle.kts", ROOT / "android/desktop-sdk/build.gradle.kts"]
    for relative in ("android/conformance/src/main", "android/desktop-sdk/src/main"):
        directory = ROOT / relative
        require(directory.is_dir() and not directory.is_symlink(), "Missing compiled client/SDK sources")
        paths.extend(path for path in directory.rglob("*") if path.is_file() or path.is_symlink())
    files = {path.relative_to(ROOT).as_posix(): file_ref(path) for path in sorted(paths)}
    require(all(freeze.get("files", {}).get(name) == record for name, record in files.items()),
            "Selected packet does not compile the exact current client/SDK source contract")
    require(set(child.CLIENT_FILES) <= set(files), "Missing observed replay client source")
    return {"source_freeze": file_ref(freeze_path), "files": files}


def input_contract(image, product, packet, receipt_sha256):
    require(IMAGE_ID.fullmatch(str(image)) and SHA256.fullmatch(str(receipt_sha256)),
            "Select immutable image ID and exact packet receipt SHA256")
    product, packet = child.fresh.literal_directory(product), child.fresh.literal_directory(packet)
    receipt = file_ref(packet / "receipt.json")
    require(receipt["sha256"] == receipt_sha256, "Selected original packet receipt changed")
    return {"image_id": image, "product": str(product), "packet": str(packet),
        "packet_receipt": receipt, "compiled_sources": compiled_sources(packet),
        "host_sources": source_contract()}


def child_record(path, contract):
    """Call the complete independent child auditor BEFORE deriving any record."""
    result = child.acceptance.audit_report(path)
    require(result == CHILD_RESULT, "Child auditor did not establish three monitors and twenty cycles")
    report = load(path); directory = path.parent
    require(report["image_id"] == contract["image_id"] and report["packet"] == contract["packet"] and
            report["product"] == contract["product"] and
            report["packet_receipt_sha256"] == contract["packet_receipt"]["sha256"],
            "Child uses a foreign image/product/packet contract")
    require(report["client_sources"]["source_freeze"] == contract["compiled_sources"]["source_freeze"] and
            report["client_sources"]["files"] == {name: contract["compiled_sources"]["files"][name]
                                                   for name in child.CLIENT_FILES},
            "Child compiled client source contract changed")
    roles = {"producer": "child_producer", "auditor": "child_auditor", "runtime_status": "runtime_status",
        "fresh_guest": "fresh_guest", "stream_mechanics": "stream_mechanics",
        "raw_window_pixel_audit": "raw_window_pixel_audit"}
    require(report["source_files"] == {role: contract["host_sources"][source] for role, source in roles.items()},
            "Child host source contract changed")
    manifest = load(directory / "image-manifest.json")
    product_manifest = load(directory / "product-candidate-manifest.json")
    sdk = product_manifest.get("emulator_runtime")
    require(isinstance(sdk, dict) and sdk and isinstance(sdk.get("files"), dict) and sdk["files"] and
            SHA256.fullmatch(str(sdk.get("sha256"))), "Original product manifest lacks bundled emulator SDK identity")
    identity = {key: report[key] for key in ("boot_id", "container_id", "container_run", "conformance_run")}
    require(BOOT_ID.fullmatch(str(identity["boot_id"])) and re.fullmatch(r"[0-9a-f]{64}", str(identity["container_id"])) and
            all(RUN.fullmatch(str(identity[key])) for key in ("container_run", "conformance_run")),
            "Malformed original actual boot/container/run identity")
    prelaunch = load(directory / "prelaunch-userdata.json")
    require(prelaunch == report["prelaunch_state"] and
            prelaunch["state"]["path"] == str(directory / "emulator-state"), "Child userdata summary differs from original")
    identity["userdata"] = prelaunch["state"]
    # SDK is inherited by the immutable image, not an injected host SDK. The
    # original complete product manifest and child offline image audit bind it.
    return {"report": file_ref(path), "image_manifest": file_ref(directory / "image-manifest.json"),
        "product_manifest": file_ref(directory / "product-candidate-manifest.json"),
        "sdk_runtime_sha256": canonical_sha256(sdk), "identity": identity, "audit": result,
        "started_monotonic_ns": report["started_monotonic_ns"], "ended_monotonic_ns": report["ended_monotonic_ns"]}


def audit_children(directory, contract):
    """Audit all original children, collecting errors without dropping failures."""
    records, errors = [], []
    for name in BOOT_DIRS:
        child_dir = directory / name
        try:
            require(child_dir.is_dir() and not child_dir.is_symlink() and child_dir.resolve(strict=True) == child_dir,
                    "Missing/aliased child directory")
            require(not any((child_dir / name).exists() or (child_dir / name).is_symlink()
                            for name in ("failure.json", "candidate-report.json")),
                    "Failed/unfinalized child attempt retained")
            path = child_dir / "report.json"
            require(path.resolve(strict=True) == path and not path.is_symlink(), "Missing/aliased original child report")
            records.append({"directory": name, **child_record(path, contract)})
        except Exception as error:
            errors.append({"directory": name, "error": str(error)})
    require(not errors, "Original child audit failed: " + str(errors))
    for key in ("boot_id", "container_id", "container_run", "conformance_run"):
        require(len({row["identity"][key] for row in records}) == 3, "Duplicate actual " + key)
    states = [row["identity"]["userdata"] for row in records]
    require(len({row["path"] for row in states}) == 3 and len({(row["dev"], row["ino"]) for row in states}) == 3,
            "Duplicate actual userdata path/directory identity")
    for key in ("image_manifest", "product_manifest", "sdk_runtime_sha256"):
        require(all(row[key] == records[0][key] for row in records), "Immutable image/SDK manifest changed across boots")
    require(all(records[index]["ended_monotonic_ns"] <= records[index + 1]["started_monotonic_ns"]
                for index in range(2)), "Fresh child boots overlap or were reordered")
    return records


def audit_report(path, expected_report_sha256):
    """An out-of-band original digest is mandatory; never trust a self-seal."""
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path and not path.is_symlink(), "Aggregate report path is not literal")
    require(SHA256.fullmatch(str(expected_report_sha256)) and file_ref(path)["sha256"] == expected_report_sha256,
            "Original aggregate report seal changed")
    directory = path.parent; report = load(path)
    required = {"schema", "kind", "scope", "status", "boot_count", "cycles_per_boot", "connectors",
        "runtime_qualified", "qualification_claimed", "separate_24h_campaign_required", "contract", "children",
        "attempts", "started_monotonic_ns", "ended_monotonic_ns", "attempt_journal"}
    require(set(report) == required and report["schema"] == 1 and report["kind"] == KIND and report["scope"] == SCOPE and
            report["status"] == STATUS and report["boot_count"] == 3 and report["cycles_per_boot"] == 20 and
            report["connectors"] == 3 and report["runtime_qualified"] is False and report["qualification_claimed"] is False and
            report["separate_24h_campaign_required"] is True, "Not a three-clean-boot bounded conformance aggregate")
    require(not (directory / "failure.json").exists() and
            {path.name for path in directory.iterdir()} == {*BOOT_DIRS, "contract-before.json", "attempts.json", "report.json",
                *(name + suffix for name in BOOT_DIRS for suffix in ("-started.json", "-ended.json"))},
            "Unsuccessful/extra child attempt or aggregate evidence was discarded/substituted")
    contract = load(directory / "contract-before.json")
    require(contract == report["contract"] == input_contract(contract["image_id"], Path(contract["product"]),
            Path(contract["packet"]), contract["packet_receipt"]["sha256"]), "Source/input contract changed since before boot one")
    attempts = load(directory / "attempts.json")
    require(file_ref(directory / "attempts.json") == report["attempt_journal"] and attempts == report["attempts"] and
            len(attempts) == 3 and [row["directory"] for row in attempts] == list(BOOT_DIRS) and
            all(row["status"] == "passed_original_child" and row["error"] is None for row in attempts),
            "Failed/skipped/reordered child attempt")
    children = audit_children(directory, contract)
    require(children == report["children"], "Aggregate summary differs from independently audited original children")
    prior = report["started_monotonic_ns"]
    for attempt, record in zip(attempts, children):
        original_start = load(directory / (attempt["directory"] + "-started.json"))
        original_end = load(directory / (attempt["directory"] + "-ended.json"))
        require(original_end == attempt and original_start == {key: value for key, value in
                {**attempt, "status": "started", "error": None, "report": None}.items() if key != "ended_monotonic_ns"},
                "Original started/ended attempt records differ from summary")
        require(set(attempt) == {"directory", "status", "error", "started_monotonic_ns", "ended_monotonic_ns", "report"} and
                attempt["report"] == record["report"] and
                prior <= attempt["started_monotonic_ns"] <= record["started_monotonic_ns"] <
                record["ended_monotonic_ns"] <= attempt["ended_monotonic_ns"], "Attempt does not bracket actual original child")
        prior = attempt["ended_monotonic_ns"]
    require(prior <= report["ended_monotonic_ns"], "Aggregate ended before children")
    return {"boot_count": 3, "cycles_per_boot": 20, "connectors": 3,
        "runtime_qualified": False, "qualification_claimed": False, "separate_24h_campaign_required": True}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-report-sha256", required=True)
    args = parser.parse_args(argv)
    import json
    print(json.dumps(audit_report(args.report, args.expected_report_sha256), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
