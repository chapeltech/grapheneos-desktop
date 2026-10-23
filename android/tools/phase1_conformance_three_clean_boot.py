#!/usr/bin/env python3
"""Produce exactly three fresh ordinary conformance-only 20-cycle boots.

Sequential, no retries, repair or reused userdata. Every failed attempt remains
at its original path. Success establishes only this bounded three-boot gate;
the separate 24-hour campaign and full runtime qualification remain required.
"""
from pathlib import Path
import json
import sys
import time

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import phase1_conformance_clean_boot as child
import phase1_conformance_three_clean_boot_acceptance as acceptance
from phase1_conformance_common import file_ref, load


def run_campaign(image, product, packet, receipt_sha256, output, transition_timeout=120):
    output = Path(output).absolute()
    acceptance.require(not output.exists() and not output.is_symlink() and
        output.parent.resolve(strict=True) == output.parent, "Never reuse campaign output or userdata")
    acceptance.require(30 <= transition_timeout <= 120, "Bounded transition timeout must be 30..120 seconds")
    contract = acceptance.input_contract(image, product, packet, receipt_sha256)
    product, packet = Path(contract["product"]), Path(contract["packet"])
    started = time.monotonic_ns(); output.mkdir(mode=0o700)
    child.fresh.write_new_durable(output / "contract-before.json", contract)
    attempts = []
    try:
        for name in acceptance.BOOT_DIRS:
            acceptance.require(acceptance.input_contract(image, product, packet, receipt_sha256) == contract,
                "Source/input contract changed before next fresh boot")
            row = {"directory": name, "started_monotonic_ns": time.monotonic_ns(), "status": "started",
                   "error": None, "report": None}
            attempts.append(row)
            child.fresh.write_new_durable(output / (name + "-started.json"), row)
            try:
                # Existing child owns all Android launch, UI consent, twenty
                # populated mixed-monitor cycles and cleanup. Never replace it.
                child.run_guest(image, product, packet, receipt_sha256, output / name, transition_timeout)
                path = output / name / "report.json"
                acceptance.child_record(path, contract)
                acceptance.require(acceptance.input_contract(image, product, packet, receipt_sha256) == contract,
                    "Source/input contract changed during child boot")
                row.update(status="passed_original_child", report=file_ref(path))
            except BaseException as error:
                row.update(status="failed_original_child", error=str(error))
                raise
            finally:
                row["ended_monotonic_ns"] = time.monotonic_ns()
                child.fresh.write_new_durable(output / (name + "-ended.json"), row)
        journal = child.fresh.write_new_durable(output / "attempts.json", attempts)
        records = acceptance.audit_children(output, contract)
        report = {"schema": 1, "kind": acceptance.KIND, "scope": acceptance.SCOPE, "status": acceptance.STATUS,
            "boot_count": 3, "cycles_per_boot": 20, "connectors": 3,
            "runtime_qualified": False, "qualification_claimed": False, "separate_24h_campaign_required": True,
            "contract": contract, "children": records, "attempts": attempts, "attempt_journal": journal,
            "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns()}
        # Audit the original final report with its returned out-of-band digest.
        # An audit failure keeps these bytes and a failure marker; no resealing.
        reference = child.fresh.write_new_durable(output / "report.json", report)
        acceptance.audit_report(output / "report.json", reference["sha256"])
        return {"report_path": str(output / "report.json"), **reference,
                "runtime_qualified": False, "separate_24h_campaign_required": True}
    except BaseException as error:
        if not (output / "attempts.json").exists():
            child.fresh.write_new_durable(output / "attempts.json", attempts)
        child.fresh.write_new_durable(output / "failure.json", {"kind": acceptance.KIND,
            "status": "failed_three_clean_boots_not_qualified", "error": str(error),
            "attempts": attempts, "runtime_qualified": False, "qualification_claimed": False,
            "separate_24h_campaign_required": True})
        raise


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--product", type=Path, required=True)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--transition-timeout", type=int, default=120)
    args = parser.parse_args(argv)
    print(json.dumps(run_campaign(args.image, args.product.absolute(), args.packet.absolute(),
        args.receipt_sha256, args.output.absolute(), args.transition_timeout), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
