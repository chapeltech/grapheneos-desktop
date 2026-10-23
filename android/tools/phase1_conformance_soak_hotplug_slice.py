#!/usr/bin/env python3
"""Actual fresh conformance guest + continuous health + exact 20 hotplug cycles.

Callable bounded vertical slice only. The whole 86400s/min3-round/nine-scenario
soak remains mandatory and is NOT implemented/qualified by this entrypoint.
"""
from pathlib import Path
import json
import sys
import time

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import phase1_conformance_clean_boot as lane
import phase1_conformance_three_clean_boot_acceptance as bindings
import phase1_conformance_soak_contract as contract
import phase1_conformance_soak_sampler as sampling
import phase1_conformance_soak_hotplug_slice_acceptance as acceptance
import run_phase1_conformance_recents_guest as wrapper
from phase1_conformance_common import canonical, file_ref
import phase1_conformance_observations as observations

require = lane.require


def input_contract(image, product, packet, receipt):
    value = bindings.input_contract(image, product, packet, receipt)
    extra = {"slice_producer": Path(__file__).resolve(), "slice_auditor": Path(acceptance.__file__).resolve(),
        "continuous_sampler": Path(sampling.__file__).resolve(), "health_observer": Path(sampling.health.__file__).resolve(),
        "health_auditor": TOOLS / "phase1_conformance_soak_health_acceptance.py", "full_soak_contract": Path(contract.__file__).resolve(),
        "raw_observations": Path(observations.__file__).resolve()}
    value["host_sources"].update({role: {"path": str(path), **file_ref(path)} for role, path in extra.items()})
    return value


class SliceProducer(lane.Producer):
    def __init__(self, *args, sampler_identity, sampler_output, sample_seconds, **kwargs):
        super().__init__(*args, **kwargs)
        self.sampler_identity, self.sampler_output, self.sample_seconds = sampler_identity, sampler_output, sample_seconds
        self.sampler = None
        self.sampler_result = None
        self.finishing_runtime = False

    def start_runtime(self):
        status = super().start_runtime()
        self.sampler = sampling.ContinuousSampler(self.sampler_identity, self.sampler_output,
            interval_seconds=self.sample_seconds)
        self.sampler.start()
        return status

    def alive(self):
        super().alive()
        if self.sampler is not None and not self.finishing_runtime: self.sampler.check()

    def runtime_command(self, phase):
        require(phase != "expect-revocation", "Ordinary hotplug runtime command cannot omit exact seven expectation fields")
        return super().runtime_command(phase)

    def finish_instrumentation(self):
        # Stop observation only after the inherited final phone-home capture,
        # before normal instrumentation teardown may retire its client process.
        self.finishing_runtime = True
        self.sampler_result = self.sampler.stop()
        return super().finish_instrumentation()


def run_guest(image, product, packet, receipt_sha256, output, transition_timeout=120, sample_seconds=30):
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and output.parent.resolve(strict=True) == output.parent,
        "Never reuse slice output or userdata")
    require(30 <= transition_timeout <= 120 and type(sample_seconds) is int and 1 <= sample_seconds <= 300,
        "Bounded slice transitions/sampling only")
    frozen = input_contract(image, product, packet, receipt_sha256)
    product, packet = Path(frozen["product"]), Path(frozen["packet"])
    client_sources = lane.bind_client_sources(packet)
    output.mkdir(mode=0o700); lane.fresh.write_new_durable(output / "contract-before.json", frozen)
    authority = {"runner": lane.fresh.source_identity(Path(__file__).resolve()),
        "guest_common": lane.fresh.source_identity(Path(lane.fresh.__file__).resolve())}
    guest = lane.fresh.Producer(image, product, packet, receipt_sha256, output, authority=authority)
    child = None; report = None; error = None; started = time.monotonic_ns()
    try:
        guest.image_manifest(); guest.inputs(); guest.start()
        before = wrapper.prepare_guest(guest)
        launch = next(row["argv"] for row in guest.trace if row.get("argv", [])[:3] == ["docker", "run", "-d"])
        running = [json.loads(row["output"])[0] for row in guest.trace if row.get("argv") ==
            ["docker", "container", "inspect", guest.container] and json.loads(row["output"])[0]["State"]["Running"] is True]
        require(running and type(running[-1]["State"].get("Pid")) is int and running[-1]["State"]["Pid"] > 0,
            "Original running container PID unavailable")
        identity = {"container_id": guest.container, "image_id": image, "container_run": guest.run,
            "boot_id": before["boot_id"], "fingerprint": before["fingerprint"], "userdata_path": str(output / "emulator-state"),
            "user": str(guest.prelaunch_userdata["state"]["uid"]) + ":" + str(guest.prelaunch_userdata["state"]["gid"])}
        identity.update(kvm_group=launch[launch.index("--group-add") + 1], container_pid=running[-1]["State"]["Pid"])
        child_dir = output / "runtime"; child_dir.mkdir(mode=0o700)
        child = SliceProducer(guest.container, image, before["boot_id"], before["fingerprint"], child_dir,
            transition_timeout, core_epochs=before["protected_processes"], sampler_identity=identity,
            sampler_output=output / "sampler", sample_seconds=sample_seconds)
        child.deadline_ns = started + lane.acceptance.MAX_BOOT_NS
        terminal = child.exercise()  # Exact existing populated all-three/20-cycle body and final phone recovery.
        after = wrapper.finish_guest(guest, before)
        sampled = child.sampler_result
        require(sampled is not None, "Continuous health evidence was not finalized before normal client teardown")
        lane.mechanics.write_new(child_dir / "commands.json", canonical(child.trace))
        require(input_contract(image, product, packet, receipt_sha256) == frozen, "Slice source/image/client contract drifted during boot")
        report = {"schema": 1, "kind": acceptance.KIND, "scope": acceptance.SCOPE, "status": acceptance.STATUS,
            "image_id": image, "boot_id": before["boot_id"], "container_id": guest.container, "container_run": guest.run,
            "conformance_run": child.conformance_run, "boot_count": 1, "cycles": 20, "fingerprint": before["fingerprint"],
            "authority": authority, "packet": str(packet), "product": str(product), "packet_receipt_sha256": receipt_sha256,
            "prelaunch_state": guest.prelaunch_userdata, "runtime_qualified": False, "qualification_claimed": False,
            "whole_campaign_complete": False, "required_campaign_seconds": 86400, "required_minimum_rounds": 3,
            "required_scenarios": list(contract.SCENARIOS), "implemented_scenarios": ["hotplug"], "contract": frozen,
            "started_monotonic_ns": started, "ended_monotonic_ns": time.monotonic_ns(), "before": before, "after": after,
            "terminal": terminal, "uids": child.uids, "stages": child.phases, "client_sources": client_sources,
            "sampler": sampled, "container_stopped": False}
    except BaseException as caught:
        error = caught
    finally:
        cleanup_errors = []
        if child is not None:
            if child.sampler is not None and not child.sampler.stop_event.is_set():
                try: child.sampler.stop()
                except Exception as caught: cleanup_errors.append(str(caught))
            try: child.stop_background()
            except Exception as caught: cleanup_errors.append(str(caught))
        if guest.container is not None:
            try: require(guest.stop(), "Owned slice guest was not stopped")
            except Exception as caught: cleanup_errors.append(str(caught))
        # If an in-flight observer could not drain before guest cleanup, its
        # owned command now fails/stops. Retain the final raw journal rather
        # than losing partial unsuccessful attempt evidence in thread memory.
        if child is not None and child.sampler is not None and child.sampler.sealed_result is None:
            try: child.sampler.stop()
            except Exception as caught: cleanup_errors.append(str(caught))
        lane.fresh.write_new_durable(output / "commands.json", guest.trace)
        if error is not None or cleanup_errors:
            if child is not None: child.seal_failure(error or ValueError("Owned cleanup failed"), "; ".join(cleanup_errors) or None)
            lane.fresh.write_new_durable(output / "failure.json", {"status": "failed_slice_not_qualified", "error": str(error),
                "cleanup_errors": cleanup_errors, "container_id": guest.container, "runtime_qualified": False,
                "whole_campaign_complete": False})
        elif report is not None:
            contexts = [(output, guest.trace, True), (output / "runtime", child.trace, False),
                        (output / "sampler", child.sampler.reader.trace, False)]
            report.update(container_stopped=True, ended_monotonic_ns=time.monotonic_ns(),
                runtime_evidence=observations.inventory(output / "runtime", output / "runtime", [(output / "runtime", child.trace, False)], guest.container),
                evidence_files=observations.inventory(output, output, contexts, guest.container))
            lane.fresh.write_new_durable(output / "candidate-report.json", report)
    if error is not None: raise error
    require(not cleanup_errors and report is not None, "Owned slice cleanup failed")
    try: acceptance.audit_report(output / "candidate-report.json")
    except Exception as caught:
        lane.fresh.write_new_durable(output / "failure.json", {"status": "failed_independent_slice_audit_not_qualified",
            "error": str(caught), "candidate_report": file_ref(output / "candidate-report.json"), "runtime_qualified": False})
        raise
    (output / "candidate-report.json").rename(output / "report.json")
    return {"report_path": str(output / "report.json"), **file_ref(output / "report.json"),
        "whole_campaign_complete": False, "runtime_qualified": False}


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    for name in ("product", "packet", "output"): parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--receipt-sha256", required=True)
    parser.add_argument("--transition-timeout", type=int, default=120)
    parser.add_argument("--sample-seconds", type=int, default=30)
    args = parser.parse_args(argv)
    print(json.dumps(run_guest(args.image, args.product.absolute(), args.packet.absolute(), args.receipt_sha256,
        args.output.absolute(), args.transition_timeout, args.sample_seconds), sort_keys=True))
    return 0


if __name__ == "__main__": raise SystemExit(main())
