# Superseding private-native review: phone/null-focus and KGC caller compatibility

2026-10-12. Status: sealed-2 acceptance is withdrawn for the selected source/host
phone-routing compatibility claim. The preceding immutable review-1 is retained
unchanged as history; its nonce/lifetime and packaging checks do not excuse this
concrete missed phone regression. No repository, source7, stage, SDK, platform
build, container, guest, key or userdata write is authorized by this review.

Rejected implementation manifest:
`512be7775dc1874fea65ad1868848fe3c89d70fc246cbf8b0b8709f812f55975`.

In sealed-2 `WonadPolicyKeyAdapter.beforeStock`, `blocked = focus == null || ...`
applies to unclaimed/phone input as well as claimed input. An ordinary phone
DOWN with no focus becomes CONSUME rather than STOCK, and the retained pair
then consumes its matching UP even after focus appears. Host phone controls in
the earlier suite used nonnull focus, so they missed this behavior.

Sealed-2 also replaced the KGC three-argument method instead of retaining a
zero-token compatibility overload. Pinned Input tests directly call the old
three-argument method; exact caller inventory will be retained with the
successor review. Full native/framework compilation remained unqualified, but
source-visible test-caller compatibility must still be preserved or explicitly
updated in a reviewed patch.

Required bounded successor controls:

- ordinary unclaimed/phone null-focus DOWN and matching UP are STOCK, including
  token-zero exhaustion;
- a stock null-focus DOWN remains STOCK through terminal after claim publication;
- a claimed null-focus DOWN is consumed and its later focused UP drains;
- a protected/contained phone display remains consumed, independently of focus;
- retained claimed lineage cannot become stock merely because current claim or
  focus disappears;
- a KGC three-argument overload delegates with zero token; only the private
  invocation-wrapped four-argument path can commit claimed native authority;
- pinned direct-call tests are inventoried; any claimed tests changing to the
  four-argument path are patched and manifest-bound.

The existing raw F1/F2, origin/incarnation, chord/collateral cancellation,
full native/JNI/runtime qualification limits remain unchanged.

## Immutable stock/API successor: qualified findings

Reviewed successor:
`phase1-private-key-admission-api-stock-successor-20261012-1/work/sealed`,
manifest SHA256
`86911f6affc9128a34f9c6a736e2aeb5ace554587471fb1f4986fdaaae818b17`,
SHA256SUMS SHA256
`d780705adaf16a07a073178ead333974a53b9d19682f74cb8e9a231ed7db12d4`.
All files/directories are read-only and have no symlinks; checksum and all
source/support/tool pins were verified. Regeneration yields the exact twelve
manifest-bound source files. Only KeyGestureController.java and
WonadPolicyKeyAdapter.kt implementation bytes differ from sealed-2; the native
implementation and ownership projection remain unchanged.

The successor corrects null-focus blocking to apply only when current/retained
claimed origins exist, and restores an internal three-argument KGC method
delegating to the four-argument method with token zero. Current source callers
of the restored direct method are pinned Input tests; the generated production
IMS caller uses four arguments with a begin/finish AdmissionCall wrapper.

Accepted narrow findings:

- ordinary phone/unclaimed null-focus DOWN/UP remains STOCK for all nine roles,
  including wrapped token-zero exhaustion;
- initial stock null-focus DOWN remains STOCK through terminal after claim
  publication; claimed null-focus input fails closed and later focused terminal
  drains; retained claimed origins and protected-phone barriers stay consumed;
- all fifteen exact direct KGC caller expressions extracted from the pinned
  tests compile in a Java/Kotlin projection and observe zero-token delegation;
- unchanged private signed63 native token, exact KeyEntry ownership transitions,
  release/reset callback checks, out-of-lock cleanup and wrapped Java rollback
  satisfy the previous bounded source/host controls. This does not extend the
  verdict to unwrapped nested direct calls (RED below).

Independent replay `successor-replay-2/result.json`:
`bc075ef6d187afe89c49b7d08448960964ab30bd885f62c9e86da954de11d3b6`.
Routing 127 / adapter 2130 / native projection 82 / direct producer source guards
151 / independent cross-file interface checks 54 / independent phone matrix 48
PASS. Literal producer entrypoint reports source 153 because it adds two final
main controls; this reviewer directly invokes the guard/replay functions and
does not conflate those counts. The 15-call projection compiles the actual
three-argument overload and exact actual call expressions, but uses a stand-in
four-argument method to observe token zero. It is signature/delegation proof,
not a complete Android Input test class or actual stock-policy body execution.
Pinned test SHA:
`f14238927f72d9b8939fcf1f707d7f7c869490146d8b3125b86d9f82932b7077`.

Ordered patch replay independently checks/applies all three patches to fresh
external copies inside isolated Git repositories and matches all twelve exact
target hashes, with original pins unchanged. Receipt:
`patch-replay-1/result.json`,
`05298bb58e9ae733fb325274452ed0c5477894f258a1d313db9a1874f97db86f`.
Earlier reviewer selector failure `successor-replay-1` is preserved; it incorrectly
selected an IMS public-long method for its KGC-overload assertion. Replay-2
corrects only that reviewer selector, not candidate bytes.

## New concrete RED: unwrapped compatibility reentry

The restored three-argument method directly calls four-argument token zero and
does not shadow an existing AdmissionCall. `beforeStock` unconditionally assigns
the current thread's call.provisional. Thus a synchronous direct compatibility
call can overwrite an outer IMS invocation's provisional pair:

1. Outer IMS call T admits exact claimed pair A before SecurePaste publication.
2. Nested unwrapped KGC three-argument call admits B. Its token-zero commit
   correctly rejects/drains B, but `beforeStock` replaced outer provisional A
   with B.
3. Outer SecurePaste throws before native commit. Outer finish(-1) drains B,
   leaving A APPLICATION; matching A UP is application input without its DOWN.

`UnwrappedCompatibilityRollbackControl.kt` compiles the actual helper/adapter
with the frozen stubs and projects the exact existing direct-call route.
Standalone Java exits 1, output:
`UNWRAPPED_COMPAT_ROLLBACK outerUpApplication=true outerUpConsume=false`.
`additional-red-results.json` records the control and binary. This is not an
observed Android runtime callback; source inventory currently has no production
three-argument caller after the IMS patch. Nonetheless, universal exact
invocation-owned rollback is NOT accepted for the direct private/test API. A
neutral compatibility AdmissionCall shadow/restoration, or equivalently proven
invocation-bound provisional registration, plus executable regression is needed
to close this edge. Producer and root were notified; no fix was made here.

## Reader census is not atomic

KGC reconcileWonadPolicyDevices independently calls getKeyCodeState for each
keycode, then helper reconcileDevices checks only helper mutationEpoch. That
epoch sees policy/lifecycle state mutations, not raw InputReader transitions.
A DOWN after its key was read UP but before policy processes it can leave the
epoch unchanged while the collected allKeysReleased result remains true.
The helper can then clear saturation and all active/retained exact drains.

`ReaderCensusBoundaryControl.kt` executes the real helper with a bounded separate
reader-state projection: saturate max-eight claimed pairs, retire their origin,
scan UP then race reader DOWN after key zero's read without helper mutation,
reconcile the unchanged epoch, then late old UP stamped phone becomes STOCK.
Standalone Java exits 1, output:
`READER_CENSUS_BOUNDARY actualReaderDown=true epochUnchanged=true oldUpStock=true`.
It demonstrates the missing reader guard; it does not claim to execute real
InputReader or reproduce scheduling on a device.

This does not change signed63 token allocation or exact native KeyEntry cleanup
ownership. It leaves saturation recovery/old-UP suppression under raw-reader
races unqualified even within the otherwise selected posttarget seam. A coherent
atomic reader census or reader generation validated across the scan, or disabling
drain-clearing recovery until such proof exists, is required for stronger claims.
Comments/tests calling this unchanged helper epoch a trusted complete native
all-UP census are not sufficient evidence.

## Final bounded verdict

Stock/null-focus correction, direct caller signature compatibility, unchanged
nonce/native lifetime protocol and patch packaging pass the enumerated narrow
source/host checks. The successor is NOT fully accepted for universal invocation
rollback or saturation-recovery drain parity: both RED boundaries above remain.
No queue-origin/device/display incarnation/final-target isolation is inferred;
raw INVALID hardware admitted at F1 external can re-resolve to F2 phone before
delivery. Stock POLICY drop synthesizes device/display cancellations across
connections (not a keycode-only cancel), so collateral key/fallback behavior is
OPEN rather than a claim of native InputState stranding. Full Android build,
JNI VM behavior, socket publication paths, image and physical runtime remain
OPEN. All prior rejected implementations/reviews and new failures are preserved.
