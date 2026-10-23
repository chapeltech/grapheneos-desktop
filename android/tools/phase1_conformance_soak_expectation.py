#!/usr/bin/env python3
"""Read exact TEST-client expectation receipts; never trigger a disturbance.

Arming/action/reopen orchestration and its original-trace auditor are unfinished.
This parser cannot certify a lock, user transition or complete soak by itself.
"""
import json
import re

import conformance_runtime as runtime
from phase1_conformance_common import strict_object

MARKER = "WONAD_CONFORMANCE_EXPECTATION "


def parse(output):
    rows = [line.split(MARKER, 1)[1] for line in output.splitlines() if MARKER in line]
    runtime.require(len(rows) == 1, "One original expectation marker required")
    value = json.loads(rows[0], object_pairs_hook=strict_object)
    if value is None: return None
    runtime.require(isinstance(value, dict) and set(value) == {"nonce", "generation", "identity_epoch", "reason", "deadline_elapsed_ms", "state"} and
        runtime.HEX32.fullmatch(str(value["nonce"])) and value["state"] in {"armed", "consumed"} and
        all(type(value[key]) is int and 0 < value[key] <= 2**63 - 1 for key in ("generation", "identity_epoch", "deadline_elapsed_ms")) and
        type(value["reason"]) is int and value["reason"] in runtime.EXPECTED_REVOCATION_REASONS, "Malformed exact expectation receipt")
    return value


def require_armed(output, run, nonce, generation, identity_epoch, reason):
    observed = parse(output); status = runtime.parse_status(output)
    runtime.require(observed is not None and observed["state"] == "armed" and
        (observed["nonce"], observed["generation"], observed["identity_epoch"], observed["reason"]) ==
        (nonce, generation, identity_epoch, reason) and status["run"] == run and status["failure"] is None and
        status["state"] == "ready" and status["runtime_readiness"] == {"ready": True, "session_open": True, "reopen_required": False} and
        status["handshake"] == {"nonce": nonce, "phase": "expect-revocation", "result": "accepted"} and
        status["snapshot"]["generation"] == generation and status["snapshot"]["identity_epoch"] == identity_epoch,
        "Exact ready lease/nonce expectation is not armed")
    return observed


def require_consumed(output, run, original):
    observed = parse(output); status = runtime.parse_status(output)
    runtime.require(observed == {**original, "state": "consumed"} and status["run"] == run and status["failure"] is None and
        status["state"] == "waiting-reopen" and status["revocation_reason"] == original["reason"] and
        status["runtime_readiness"] == {"ready": False, "session_open": False, "reopen_required": True} and
        status["snapshot"]["generation"] == original["generation"] and status["snapshot"]["identity_epoch"] == original["identity_epoch"],
        "Next actual callback was not the exact original planned revocation")
    return observed
