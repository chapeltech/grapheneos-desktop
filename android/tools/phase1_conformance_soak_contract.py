#!/usr/bin/env python3
"""Private policy-free soak contract/scheduler core; not a live producer yet.

No production service, Haskell policy, Android launch, signing or repair path.
Unimplemented disturbance drivers fail explicitly, rather than returning a pass.
"""
from pathlib import Path
import time

DURATION_SECONDS = 86400
MINIMUM_ROUNDS = 3
SCENARIOS = ("hotplug", "credential_sleep", "credential_key", "user_switch",
    "frozen_client", "systemui_death", "client_death", "apk_update", "malformed_calls")
PROCESS_NAMES = {"system_server": "system_server", "systemui": "com.android.systemui",
    "launcher": "com.android.launcher3", "client": "org.wonad.desktop", "phone": "com.android.phone"}
RESTART_POLICY = {"hotplug": set(), "credential_sleep": set(), "credential_key": set(),
    "user_switch": {"launcher", "client"}, "frozen_client": set(), "systemui_death": {"systemui"},
    "client_death": {"client"}, "apk_update": {"client"}, "malformed_calls": {"client"}}
REQUIRED_RESTART = {"systemui_death": {"systemui"}, "client_death": {"client"},
    "apk_update": {"client"}, "malformed_calls": {"client"}}
# Exact original documented bounds; no reset at intentional process replacement.
HEALTH_POLICY = {"minimum_stable_samples": 2, "minimum_stable_span_ns": 1_000_000_000,
    "maximum_sample_collection_ns": 480_000_000_000, "maximum_sample_gap_ns": 600_000_000_000,
    "maximum_sample_edge_ns": 600_000_000_000, "maximum_sample_clock_divergence_ns": 300_000_000_000,
    "maximum_fd_growth_per_incarnation": 64, "maximum_rss_growth_kib_per_incarnation": 256 * 1024,
    "maximum_task_growth_per_run": 12, "maximum_root_growth_per_run": 8,
    "maximum_cumulative_fd_residual": 64, "maximum_cumulative_rss_residual_kib": 256 * 1024}
MAX_SCENARIO_NS = 1800_000_000_000
MAX_CHECKPOINT_NS = 660_000_000_000
MAX_IDLE_NS = 600_000_000_000
MAX_CAMPAIGN_NS = (DURATION_SECONDS + 4 * 3600) * 1_000_000_000

IMPLEMENTATION_STATUS = "incomplete_disturbance_drivers_and_semantic_audits_not_runtime_qualified"
MISSING = {
    "hotplug": "Repeatable populated three-monitor round and raw audit are implemented; wire the held-runtime round into the complete disturbance campaign and execute on the source-matched image",
    "credential_sleep": "Exact LOCKED callback, credential lifecycle, black/input shield and fresh descriptive restore actor/raw audit are implemented; complete campaign integration and actual Android execution remain required",
    "credential_key": "Lock-key actor/raw audit preserves generated credential cleanup and stable protected epochs; complete campaign integration and actual Android execution remain required",
    "user_switch": "Ordinary test-user lifecycle, independently admitted role UIDs, black/input shield and exact USER_CHANGED recovery actor/raw audit are implemented; complete campaign integration and actual Android execution remain required",
    "frozen_client": "Exact STOP/expiry/CONT actor and raw audit, repeated black/input shields, unchanged client epoch and fresh descriptive restoration are implemented; signed packet15 contains reason-5 support, while full campaign integration and actual source-matched Android execution remain required",
    "systemui_death": "Exact TEST broker-death recipient and nonce-bound recovery are compiled in genuine development packet16; scoped actor/raw auditor and continuous-health transition are under review, with source-matched runtime and full campaign integration still required",
    "client_death": "Exact client-death actor/raw audit and fresh current-token copied-frame recovery are implemented as a bounded version1 attachment; reviewed role-death sampler, actual source-matched runtime, externally admitted current-version handling and full campaign integration remain required",
    "apk_update": "Current signed version-only pair, ordinary update/restore actor, exact copied-frame recovery, durable epoch canary and opt-in continuous-health raw consumer are implemented; full campaign integration and actual Android execution remain required",
    "malformed_calls": "Challenge-bound neutral foreign/stale/malformed RPC actor and raw audit are implemented and genuinely compiled privately; new signed packet admission, current-version handling, common continuous-health integration and actual source-matched whole-campaign execution remain required",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def should_continue(started_ns, rounds, now_ns):
    require(all(type(value) is int for value in (started_ns, rounds, now_ns)) and
        started_ns > 0 and rounds >= 0 and now_ns >= started_ns, "Invalid original soak clock")
    return rounds < MINIMUM_ROUNDS or now_ns - started_ns < DURATION_SECONDS * 1_000_000_000


def epoch_transitions(name, before, after):
    require(name in SCENARIOS and set(before) == set(after) == set(PROCESS_NAMES), "Missing protected role/unknown scenario")
    changes = []
    for role in PROCESS_NAMES:
        old, new = before[role], after[role]
        require(all(isinstance(row, dict) and set(row) == {"pid", "start_ticks"} and
            all(type(row[field]) is int and row[field] > 0 for field in row) for row in (old, new)), "Malformed actual epoch")
        if old != new:
            require(role in RESTART_POLICY[name], "Unexpected protected epoch change: " + role + " during " + name)
            changes.append({"role": role, "before": old, "after": new})
    require(REQUIRED_RESTART.get(name, set()) <= {row["role"] for row in changes}, "Required actual replacement missing")
    return changes


class PendingDisturbanceDrivers:
    """Honest capability boundary. This cannot be selected as a real soak lane."""
    def require_complete(self):
        raise NotImplementedError(IMPLEMENTATION_STATUS + ": " + "; ".join(name + ": " + MISSING[name] for name in SCENARIOS))

    def perform(self, name, ordinal):
        require(name in SCENARIOS, "Unreviewed disturbance")
        raise NotImplementedError(MISSING[name])


def schedule_complete_rounds(driver, *, monotonic_ns=time.monotonic_ns, realtime_ns=time.time_ns):
    """Testable loop core; actual driver/admission/audit integration is pending.

Readiness is checked before any sample or mutation. Short durations, skipped
actions or a product sampler cannot satisfy this fixed original contract.
"""
    driver.require_complete()
    began, real_began = monotonic_ns(), realtime_ns()
    baseline = driver.checkpoint(0)
    rounds = []
    while should_continue(began, len(rounds), monotonic_ns()):
        ordinal = len(rounds) + 1
        actions = [driver.perform(name, ordinal) for name in SCENARIOS]
        checkpoint = driver.checkpoint(ordinal)
        rounds.append({"ordinal": ordinal, "scenarios": actions, "checkpoint": checkpoint})
    ended, real_ended = monotonic_ns(), realtime_ns()
    require(ended - began >= DURATION_SECONDS * 1_000_000_000 and
        real_ended - real_began >= DURATION_SECONDS * 1_000_000_000 and
        abs((ended - began) - (real_ended - real_began)) <= HEALTH_POLICY["maximum_sample_clock_divergence_ns"] and
        ended - began <= MAX_CAMPAIGN_NS, "Whole-boot original dual-clock duration not completed")
    # No result here is an accepted report. Raw scenario audits/admission still
    # must be implemented before a later producer may publish a success.
    return {"implementation_status": IMPLEMENTATION_STATUS, "runtime_qualified": False,
        "qualification_claimed": False, "baseline": baseline, "rounds": rounds,
        "started_monotonic_ns": began, "ended_monotonic_ns": ended,
        "started_realtime_ns": real_began, "ended_realtime_ns": real_ended}
