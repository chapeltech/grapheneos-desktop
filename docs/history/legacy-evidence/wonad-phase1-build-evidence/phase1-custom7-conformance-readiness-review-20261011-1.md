# Phase-1 custom-7 fresh-conformance readiness review

Date: 2026-10-11

Scope: bounded, read-only review of the fresh full-API guest and genuine
Launcher/Recents guest paths. No image, container, guest, compiler or Android
build was started. This note is not runtime evidence.

## Reviewed identities

- Client packet: `android/out/phase1-emulator-client-packet-20261011-3`
  - receipt SHA-256: `986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad`
  - strict schema-2 validation with `live_tools=False` passed against the
    retained packet tree: 11 artifacts, 262 files, 158 source files.
  - status remains
    `compile_qualified_development_packet_not_runtime_qualified`.
  - The packet can be reused; the host driver/auditor correction below does
    not change an APK.
- Required emulator SDK directory:
  `/srv/wonad-os36-parked-home-1/mournblade-qt-fence-lifetime-1/emulator`
  - retained tree SHA-256:
    `87041e2fffb048b889d579164c5646bb1e7316fcb01db42f0ab40997786d4f13`
  - receipt:
    `android/out/emulator-qt-fence-renderer-20261009-1/receipt.json`
  - receipt SHA-256:
    `878f5a06b0643a4626d3bec3a194b79f542fab5ec4ab02b84d0370f979485f09`
- Pinned local SDK base image:
  `sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f`
  (linux/amd64). The native candidate invocation must use the explicit
  `--emulator-directory` above; do not substitute a similarly named SDK.
- `/dev/kvm` was readable and writable by the reviewing process. No host
  listener occupied emulator ports 5580/5581 at review time. The live custom-7
  OS build must finish before either 8-GiB guest is run, and the two fresh guest
  lanes must be serialized.

## Confirmed good boundaries

Both launchers require a new output directory below `android/out`, exclusively
create private `emulator-state/tmp`, seal its exact empty prelaunch inventory,
and launch one exact unprivileged, capped KVM container. The release index
requires API, Recents and runtime campaign run IDs, boot IDs and container IDs
to be pairwise distinct and requires the API and Recents retained userdata
paths to differ.

Both fresh lanes prove initial absence of the conformance, fixture and fault
packages; install only the conformance and fixture APKs with exact
`adb install --user 0`; forbid replacement, downgrade, uninstall, data-clear
and secure-setting seeding; and retain terminal package-path and APK-hash
readback. The conformance APK is an exact normal `/data/app` artifact with no
privileged or shared-UID manifest attribute, is byte-bound to packet 3, and
has the same certificate as packet 3's product Wonad. Product Wonad is absent
from the derived image. Consent is obtained by one bounded tap on the exact
enabled SystemUI `Enable Wonad desktop` control and is replayed from the raw UI
hierarchy and command journal.

The candidate builder binds the exact custom product, strict x86
baseline/custom comparison and receipts, packet-3 receipt/tree, product APK,
development signer, product fingerprint and explicit SDK runtime. The derived
conformance image preserves that native-candidate ancestry while removing the
product APK. API producer/common/auditor bytes are copied into the derived
image and checked against current reviewed files. Recents producer/auditor and
outer runner/common bytes are sealed and independently compared with current
reviewed host files. A candidate built before any host-driver correction is
therefore not suitable for the corrected API lane, but packet 3 does not need
rebuilding.

## Concrete blocker: ordinary runtime UID is not proved

`phase1_conformance_recents_acceptance.package_uids()` currently accepts each
UID merely when `0 < uid < 200000` and the four observed UIDs differ. The
current function accepts the following prohibited client identity:

```text
package:org.wonad.desktop uid:1000
package:org.wonad.fixture uid:10001
package:com.android.launcher3 uid:1002
package:com.android.systemui uid:1001
```

The exact current-code reproducer is:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tools python3 - <<'PY'
import phase1_conformance_recents_acceptance as a
raw = '''package:org.wonad.desktop uid:1000
package:org.wonad.fixture uid:10001
package:com.android.launcher3 uid:1002
package:com.android.systemui uid:1001
'''
print(a.package_uids(raw))
PY
```

It returns all four identities instead of rejecting `org.wonad.desktop`.
The full-API producer/auditor records installed paths and hashes but records no
raw installed-package UID at all. Consequently the retained evidence does not
yet prove that either fresh guest assigned the test client an ordinary user-0
application identity, even though the exact APK manifest itself is normal.

### Minimal correction proposed (not implemented by this review)

1. In the common full-API producer, after the two successful fresh installs
   and before consent/instrumentation, issue exact raw user-0 package-manager
   queries for `org.wonad.desktop` and `org.wonad.fixture`:
   `cmd package list packages -U --user 0 PACKAGE`. Retain the unmodified
   command outputs in the existing `commands.json`; no new top-level report
   field is needed.
2. For each derived UID, issue the exact user-0 reverse query
   `cmd package list packages -U --user 0 --uid UID`. Require its complete
   output to contain only the exact package. This proves no installed package
   aliases the assigned UID. The already sealed exact APK bytes and packet
   manifest prove the package name, signer and absence of a shared-UID
   declaration. Optionally also retain `dumpsys package PACKAGE` and require
   its one exact package block to have `appId=UID`, the installed `codePath`,
   and no `sharedUser=` line; the pinned PackageManager dump implementation
   emits those exact fields.
3. In the API auditor, consume those exact trace rows in their bounded
   post-install/pre-instrumentation position. With the already raw-proved sole
   active user 0, require both full UIDs/appIds to be integers in Android's
   pinned `FIRST_APPLICATION_UID..LAST_APPLICATION_UID` range
   `10000..19999`, distinct, and singleton in reverse lookup. This excludes
   system/special, SDK-sandbox and isolated identities. Explicitly join each
   package and UID to its existing `/data/app/.../base.apk` path/hash and the
   candidate artifact's certificate/no-shared-UID fields.
4. In the Recents producer, add `--user 0` to the four existing UID reads and
   add the same reverse lookup (and, if selected, package-dump) observations
   for the client and fixture. Keep the existing `uids` report field and
   `identity/package-uids.txt`; no top-level schema change is necessary.
5. In the independent Recents auditor, require only the client and fixture to
   be ordinary `10000..19999`; Launcher/SystemUI may legitimately have
   platform/system assignments but must remain distinct from both clients.
   Reconstruct the singleton/no-shared identity from raw commands and join it
   to the existing installed-APK hashes and candidate signer records. The
   outer Recents auditor should admit and replay only the new exact command
   grammar.

Focused regressions belong in
`android/tests/test_phase1_fresh_conformance.py` and
`android/tests/test_phase1_conformance_recents.py`, with outer command-grammar
coverage in `android/tests/test_phase1_conformance_recents_guest_acceptance.py`
and producer-shape coverage in
`android/tests/test_run_phase1_conformance_recents_guest.py`. Required hostile
cases: UID 1000, UID 99000, UID above 19999, a cross-user full UID, duplicate
UID/reverse alias, absent or duplicate raw rows, package/path mismatch,
`sharedUser=` package dump, and signer/hash substitution. Positive controls
must use two distinct user-0 UIDs in 10000..19999 and the actual producer argv.

## Required launch order after correction and custom-7 build

No custom-7 native or derived conformance candidate/report existed under
`android/out` at review time. First obtain the successful custom-7 receipt,
exact product directory and passing baseline/custom comparison. Then build an
unqualified strict native candidate (all paths/hashes below must be the newly
authenticated custom-7 values):

```sh
python3 android/container/build-native-candidate.py \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --apk "$PWD/android/out/phase1-emulator-client-packet-20261011-3/wonad.apk" \
  --output "$PWD/android/out/phase1-native-candidate-custom7-1" \
  --base-image sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f \
  --emulator-directory /srv/wonad-os36-parked-home-1/mournblade-qt-fence-lifetime-1/emulator \
  --phase1-build-evidence \
  --phase1-comparison "$EXACT_CUSTOM7_COMPARISON" \
  --phase1-comparison-sha256 "$CUSTOM7_COMPARISON_SHA256" \
  --phase1-baseline-receipt "$EXACT_BASELINE_RECEIPT" \
  --phase1-baseline-receipt-sha256 "$BASELINE_RECEIPT_SHA256" \
  --phase1-custom-receipt "$EXACT_CUSTOM7_RECEIPT" \
  --phase1-custom-receipt-sha256 "$CUSTOM7_RECEIPT_SHA256" \
  --phase1-client-packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --phase1-client-packet-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad \
  --tag wonad:native-v3-candidate-phase1-custom7-1
```

Use the immutable image ID printed by that command, not merely the tag:

```sh
python3 android/container/build-phase1-conformance-candidate.py \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad \
  --base-image "$NATIVE_CANDIDATE_IMAGE_ID" \
  --output "$PWD/android/out/phase1-conformance-candidate-custom7-1" \
  --tag wonad:phase1-conformance-candidate-custom7-1
```

Then serialize the two fresh guests. Each output directory must be absent:

```sh
python3 android/tools/phase1_conformance_guest.py \
  --image "$CONFORMANCE_IMAGE_ID" \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad \
  --output "$PWD/android/out/phase1-conformance-api-custom7-1"

python3 android/tools/phase1_conformance_acceptance.py \
  --report "$PWD/android/out/phase1-conformance-api-custom7-1/report.json" \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad

python3 android/tools/run_phase1_conformance_recents_guest.py \
  --image "$CONFORMANCE_IMAGE_ID" \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad \
  --output "$PWD/android/out/phase1-conformance-recents-custom7-1"

python3 android/tools/phase1_conformance_recents_guest_acceptance.py \
  --report "$PWD/android/out/phase1-conformance-recents-custom7-1/report.json" \
  --product "$EXACT_CUSTOM7_PRODUCT" \
  --packet "$PWD/android/out/phase1-emulator-client-packet-20261011-3" \
  --expected-receipt-sha256 986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad
```

Do not invoke either guest until custom-7 has completed, the corrected host
sources are frozen, and a fresh derived conformance candidate has sealed those
API producer/auditor bytes. These lanes require Docker and KVM but no host X11,
xdotool or Pillow. Their passing reports remain bounded conformance evidence,
not runtime/hardware qualification, until the required runtime campaign and
aggregate release index also pass.
