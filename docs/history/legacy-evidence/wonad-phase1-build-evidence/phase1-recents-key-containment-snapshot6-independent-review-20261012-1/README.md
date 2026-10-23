# Snapshot 6 independent key-containment review

This is a bounded review of the immutable external candidate at
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-6`.
It does not modify or qualify an Android source tree, OS image, SDK, APK, or
runtime.

## Bound inputs

- snapshot `SHA256SUMS`:
  `7e71b4768567ff4db7bb58626a11266bfb710ac539cd28548f9343b7c8d88be6`
- snapshot receipt:
  `4eb2b130caa1ae9c5cd035e6e02c5b71f80e1a3578a969ea8fa5284e12f9b8eb`
- pure helper:
  `de40b7e9ca786a68b6c9d8bf94518eaed9d782b8c125e24a09053723fbf525f2`
- adapter:
  `bb66b5747142a8c4fd59c6d35dc2e991227bfce3c660b797b9abd63fc2e0defe`
- generated `KeyGestureController.java`:
  `dcf667365a6a78317f7a2d3758433e8421b59d230e29739af5c2fae9c9995e61`
- generated `WonadUiBridge.kt`:
  `7215ee2a8697ffe418f38780937a95f665c8a269c1fb62c006573ac6c35094b2`
- snapshot-local test driver:
  `88c5d1499cfcf133b4585a46941cb0984c2d43ca651789206035f3bf785129fa`
- Kotlin launcher:
  `64d62a197fbec5f32f77c6724cce33ead4034b2ec3f873c056cde19fe00f324e`
- Java launcher:
  `cfa21aeadd00925925c9e1287f5c08f3e04ee7f26a9e23d9dbfb16149153d842`

`sha256sum -c SHA256SUMS` passed for every snapshot member. The literal
snapshot-local replay completed with `RESULT 71 bounded candidate checks
passed`. This is host/source evidence only.

## Confirmed callback-failure defect

`installAltTabStarted` publishes the pure owner, invokes the generated Java
callback while holding the lifecycle monitor, and on an exception merely
removes the pure owner (helper lines 560--585). The generated callback first
publishes `mWonadPendingAltTabOwner` and the stock pending boolean, then invokes
`handleKeyGesture(... ACTION_GESTURE_START ...)` (generated KGC lines
1311--1324). If that later operation throws, the helper forgets the owner but
does not roll back or return its cleanup. A subsequent exact-claim retirement
therefore has no owner from which to emit the required cancelled completion,
while the Java mirror and possibly emitted START remain.

`InstallCallbackFailureRepro.kt`
(`f907e35d339be6b095f98c57add88caeac447e4962523e6b754b7a1a7a8afefb`)
compiled directly with the immutable pure helper using a 256 MiB Kotlin heap
and ran with a 128 MiB Java heap. It deterministically observed:

```text
CONFIRMED callback failure strands published Alt-Tab mirror/START without retirement cleanup
```

The same rollback boundary is relevant to the Recent and Escape callbacks,
which also perform stock-action work after owner installation. A successor
must preserve the original exception while performing exact compensating
cleanup/cancellation for any externally published owner/action; simply
deleting the helper owner loses the only cleanup authority.

## Limits

- No full Android compile, Binder/Looper execution, inputflinger test, or guest
  was run.
- The fixture proves the helper/generated-callback state transition, not that a
  particular production callback operation will throw in a healthy boot.
- Snapshot 6 remains immutable historical evidence and should not be edited.
