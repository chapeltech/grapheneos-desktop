# Phase 1 key-containment integration closure

This directory is a reviewable, external-only projection of snapshot 8 onto
the exact current complete-stage prefix. It has not been applied to the Wonad
repository, GrapheneOS source7/custom7, a stage contract, SDK, image, emulator,
or device. Its JVM fixtures are not Android runtime qualification.

## Intended integration

`patches/wonad-policy-key-containment-framework.patch` is rooted at
`frameworks/base`. It changes only:

- `InputManagerService.java`: +1/-1 line;
- `KeyGestureController.java`: +547/-128 lines;
- `PhoneWindowManager.java`: +36/-2 lines.

The patch is intended to be appended immediately after the already-reviewed
`wonad-authoritative-focus-framework.patch`. The current full framework plan
projects the three preimages byte-for-byte to the authenticated custom7
inputs; the focus patch touches only Shell/Transitions and does not overlap.
This closure does **not** edit `stage_contract.py`.

`patches/wonad-policy-key-containment-input-integration.patch` is rooted at
the Wonad repository. It changes:

- `WonadInputBridge.kt`: +32/-1 lines;
- `WonadUiBridge.kt`: +29/-5 lines;

and adds the canonical Kotlin state/adapter:

- `WonadPolicyKeyContainment.kt`: 888 lines;
- `WonadPolicyKeyAdapter.kt`: 344 lines.

The existing `wonad-input-kotlin` source glob already includes both additions;
no `Android.bp`, public SDK, Binder, AIDL, or wire change is needed. The Java
delta is confined to the AOSP classes that own stock policy state/actions and
the one constructor dependency. All new pair/claim/owner state is Kotlin.

## Verification

From any directory, run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-integration-closure-20261012-1/verify_closure.py

PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-integration-closure-20261012-1/test_candidate.py
```

The first command authenticates the complete framework prefix, all source and
snapshot inputs, both patch inventories, applies both patches to fresh
temporary git repositories, and requires all seven exact result hashes. The
second is the literal self-contained 80-case bounded Kotlin/JVM and extracted
Java replay. `source-map.json` and `coverage-map.json` bind every input,
fixture, result, and independent review.

## Lock and callback ordering

See `LOCK-ORDER.md`. In short, UI lifecycle changes enter the pure helper while
holding the WMS global lock, but the inverse edge is absent in the pinned
sources. Monitored owner installation calls only identity-local Java mirror
work plus scoped gesture delivery; remote gesture delivery is AIDL `oneway`,
and the only same-process APP_SWITCH/Alt-Tab handler paths call
`StatusBarManagerInternal`, not WMS. Lifecycle cleanup is posted only after the
synchronized state transition returns. These claims are source-pinned and must
be re-reviewed if any handler, resolver, or lock path changes.

## Required work after review

Application requires a separately reviewed repository patch/stage-contract
change, pristine full-plan staging, an Android platform compile, the affected
platform test suites, a new OS build, and fresh real runtime qualification.
No result in this directory closes any of those gates.

