# Dedicated fresh-guest Recents lane

This lane exercises phone Recents with the policy-free conformance APK rather
than product Wonad. It is separate from the one-shot full-API guest, the three
20-cycle clean boots, the fault matrix and the uninterrupted 24-hour soak.
Host tests do not prove any of those runtime requirements.

First finish and authenticate the source-matched OS build, product candidate
and derived `phase1_fresh_guest_conformance_candidate_v1` image. Select the
immutable derived image ID and the exact product directory in its manifest.
Do not use a historical API3 image with the newly frozen SDK or substitute
existing emulator userdata. Only one backend guest may run within the current
memory budget. No new qualified OS image is claimed by this document.

```sh
python3 android/tools/run_phase1_conformance_recents_guest.py \
  --image "$CONFORMANCE_IMAGE_ID" \
  --product "$EXACT_CUSTOM_PRODUCT_DIRECTORY" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad \
  --output "$PWD/android/out/phase1-conformance-recents-first-1"
```

The output must not already exist. The launcher authenticates the image,
packet and product before creating a new isolated KVM container. It checks
that all test packages are absent, unlocks the credential-free phone, installs
only the ordinary fixture and conformance APKs, and enables consent by tapping
the real SystemUI control. It does not attach a display or start the one-shot
conformance test during setup: the Recents producer owns its three displays and
long-lived runtime instrumentation. No settings are seeded and the platform
fault APK remains uninstalled.

Before launching, the shared fresh-guest producer exclusively creates private
`emulator-state/` and `tmp/` directories and seals `prelaunch-userdata.json`.
That canonical record binds creation/inventory times, directory device/inode,
mode/owner, the exact empty prelaunch inventory and current runner/common
source identities. One hash/size-bound local trace row immediately precedes
Docker launch. The independent outer auditor reopens that record, checks the
same retained directory identities (not postboot emptiness), and reconstructs
boot polling, genuine consent, raw guest identities and exact container
launch/running/shutdown inspections. A caught boot-poll timeout must retain its
typed ten-second observation; it cannot stand in for eventual boot completion.

The child producer/auditor cover exact-task transfer to each destination,
cancellation, task removal, removed/stale display choices, unavailable session,
Screenshot and Split screen. Raw input, UI, task, broker, display and framebuffer
evidence must agree. Both fresh lanes now record exact user-0 forward package/UID
queries and reverse singleton UID ownership queries. Their independent auditors
require the conformance and fixture packages to have distinct ordinary Android
application IDs (10000 through 19999), and join those identities to the exact
installed `/data/app` bytes, manifest signer and non-shared/non-privileged
metadata. System, isolated, SDK-sandbox, cross-user, aliased, duplicate and
missing identities fail closed. The wrapper independently audits the sealed
child report, then checks the same boot, protected-process epochs, installed APK
bytes and five guest OS artifacts across setup and execution. Only its own
instrumentation and exact owned container are stopped; userdata is retained for
diagnosis.

The wrapper result is orchestration evidence, explicitly not runtime or
hardware qualification. `recents/report.json` remains the independently audited
lane report; `guest/` retains fresh setup, identities, command log and state.
Failure produces `failure.json`, never a passing wrapper report.

The child producer/auditor's 48 hostile-evidence tests, the direct launcher's
17 host boundary tests and CLI help pass. The separate one-shot API lane has
68 host tests, including production-generated launch/state/timeout traces and
hostile raw-identity, package, consent and container inspection mutations.
The outer Recents auditor and aggregate release gate now independently replay
and bind both fresh lanes, image ancestry, exact build/product/packet/SDK
identities and distinct guest/run/boot identities. Publication rehashes the
packet, selected product and transitive raw evidence, not only summary files.
These are host-only results: no custom-7 guest has executed this identity proof.
The immutable packet-3 APK artifacts remain reusable, but the derived
conformance candidate must be rebuilt after these producer/auditor source
changes. No qualifying fresh-image execution exists yet; standalone host
success cannot close the Phase-1 exit gate.

Container inspection grammar was checked against a real Docker 29.7.2
create-only diagnostic in
`android/out/phase1-docker-inspect-create-only-20261011-1/`. No guest was started;
the exact diagnostic container was removed. Its actual ulimits are sorted
`core` then `nofile`, while the launch argv has the reverse order: auditors
check exact unique names/typed values rather than list order. The state is one
private bind mount; the temporary filesystem is in `HostConfig.Tmpfs`, not the
bind list. This observation is not emulator qualification.

These records assume a trusted local runner, filesystem and Docker daemon.
They detect changed or contradictory retained evidence, but are not an
external attestation against an adversarial host that can replace and reseal
all files. In particular, directory inode observations do not eliminate an
adversarial seal-to-bind-mount path replacement. Private exclusive directories
and the fixed reviewed producer are the operational boundary; do not describe
this lane as proving execution against a malicious host.
