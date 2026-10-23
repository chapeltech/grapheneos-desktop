# Independent native nonce/lifecycle review

Date: 2026-10-12

Status: ACCEPTED only for the selected private post-target admission-token
source/host protocol and exact external patch reproduction bound below.
This is not native/framework build, actual JNI/runtime, full input isolation,
or app-target qualification. Mutable producer bytes were inspected only to
identify review controls, not as final proof. No repository, custom-7 source,
staging tree, SDK, container, platform build, guest, runtime key, or userdata
write was made. All generated/test writes are preserved in this new external
review directory.

## Final immutable verdict

Reviewed payload:

`/u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-7/sealed-2`

MANIFEST.json SHA-256:
`512be7775dc1874fea65ad1868848fe3c89d70fc246cbf8b0b8709f812f55975`.

SHA256SUMS SHA-256:
`ff584be0e8dcb751a873f7edaf26bc0a3c5723fa5495897bdaf32e0f814f9e2b`.

The manifest/checksums, read-only/no-symlink seal, authenticated original and
support sources, tool pins, and source-manifest pin were independently checked.
Regeneration into `replay-2/generated` reproduced all twelve frozen files
byte-for-byte. Independent replay passed routing 127, nonce adapter 2108, and
extracted native lifetime 82 checks. Calling the producer's source guards and
compile/replay routines directly passed 131 checks (its literal CLI has two
additional main-only checks). The independent cross-file verifier passed 55
checks: C++ policy/fake/JNI declaration and definition parity, Java IMS/KGC
signatures, exact method-bound JNI descriptors and scalar order, Java-time
conversion, ownership/release/exhaustion, exact rollback/pair drain, and
reference-exact neutral reentrant shadow controls.

`patch-replay-3` independently checked and applied all three ordered patches
only to fresh isolated external Git projects seeded from authenticated
original copies. The target union is exactly base 3 + native 5 + integration 4,
and every one of the twelve targets matches its manifest hash and generated
bytes. Original source hashes were rechecked after application.

The requested source/host controls are satisfied: native signed63 monotonic
nonzero nonce/no wrap or reuse; nonce-primary bounded authority; commit after
SecurePaste; invocation-owned compare-record rollback plus exact provisional
pair drain; PENDING to one successful FOREGROUND to TAKEN; outside-lock
completion; monitor isolation; abort while unhandled is unlocked; malformed
negative/oversized result fail-close; token-zero phone STOCK; capacity/terminal
and stock-cancellation distinction; fresh derived entries do not copy authority;
fresh injected fallback-bit cleanup; neutral reentrant stock and copied-Java
reference isolation. No remaining defect was found in this selected protocol.

Earlier `sealed/` is rejected as final packaging because its added integration
files lacked new-file-mode headers. Its code/host replay is preserved in
`replay-1`; sealed-2 implementation bytes are identical and its packaging is
corrected. `patch-replay-2` is a preserved reviewer-fixture failure, not a
candidate failure: it initially discovered the evidence directory's parent
Git root and silently skipped patches. The independent target-byte check
caught that no-op. `patch-replay-3` creates isolated external repositories and
verifies their roots before applying; it passes.

### Unresolved dispatch/runtime behavior

Raw INVALID-display F1-external to F2-phone delivery, queue-origin proof,
final-target/focus epoch, physical device/display generation/incarnation and
reuse, device-agnostic/default-display safety-chord effects, collateral
same-device/raw-display cancellation and cancellation/fallback behavior remain
OPEN. Full native/framework compile, actual JNI VM exceptions, real target
selection/socket publication/queue fault injection, and Android physical-device
runtime acceptance are not established by these fixtures. The host labels for
publish error, pipe-full, removal and drains exercise their common release
path; convergence from the real paths was checked in pinned stock source, not
executed through an actual InputPublisher. This acceptance cannot be promoted
to total phone/app isolation or full-image/runtime qualification.

Preserved execution receipts are `replay-2/result.json` and
`patch-replay-3/result.json`. The criteria and source findings below explain
the controls incorporated before the final seal.

## Preserved scope

This review read the complete prior admission-lifetime note:

`../phase1-native-key-admission-lifetime-review-20261012-1/README.md`

SHA-256: `7e7105ef9e537cfb6abc7079e1ef06e01f612a8d7ecd81456ef7c77f62166650`.

The source observations below are bound to the preserved tree:

`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`

| Source | SHA-256 |
| --- | --- |
| `frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp` | `4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9` |
| `frameworks/native/services/inputflinger/dispatcher/Entry.h` | `57aa994e65bfeebdceec811dd2bd380c6918508df93ce4799b3e682c433442b0` |
| `frameworks/native/services/inputflinger/dispatcher/InputState.cpp` | `ba322dd34e39f4421147a3187382bded3721b9a0f747a0c12e1b2462209115b8` |
| `frameworks/native/libs/input/Input.cpp` | `ccefd7c264aba506250b4f485dbfcdb5b1cac81becf8775ea68fc17f8ac8a4c4` |
| `frameworks/native/include/input/Input.h` | `c7ee07df6681bc7d0045465fcfae838a964f6fac678cd21a901f18ad29a87870` |
| `frameworks/base/core/java/android/view/InputEvent.java` | `539e294674bf2dfab789728c1edb116f6d7d1bc942483f861154d797417d9866` |
| `frameworks/base/core/java/android/view/KeyEvent.java` | `1f4ac4a6b669e19046e1c925e71d77938edf8575f87900d84d411403956e914b` |
| `frameworks/base/core/jni/android_view_KeyEvent.cpp` | `39115d46e379cc96bcf212ce2c789f17f3316b27de92f08bcc4790b025b3f7eb` |
| `frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp` | `0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5` |

## Additional required control: release while admission callback is unlocked

`doInterceptKeyBeforeDispatchingCommand` (InputDispatcher.cpp:6877) receives a
strong reference-backed exact `KeyEntry`, then releases `mLock` while calling
the policy. That reference keeps the C++ object alive; it does not prove the
entry remains admitted to an inbound queue.

`setInputDispatchMode(false)` (5956) and `setInputFilterEnabled` (5988) can run
concurrently under `mLock`. They call `resetAndDropEverythingLocked` (6266),
which releases `mPendingEvent` and drains the inbound queue (6275-6276).

The required hostile interleaving is therefore:

1. Native allocates token T for exact entry E, releases `mLock`, enters policy.
2. Native reset releases E while its claimed ownership is still `NONE`.
3. Policy installs the exact Java record for T and returns private `-3`.
4. Native reacquires `mLock` and tries to mark E `PENDING`.

Without an exact inbound-release/cancellation control, step 4 creates an
orphaned pending authority with no future inbound or dispatch release path.
The successor must instead reject the now-released exact entry and retire
only T outside `mLock`. This control must cover callback exception/malformed
return as well as successful claimed return.

A check of `mPendingEvent == E` alone is insufficient. Focus updates
(`enqueueFocusEventLocked`, 1795) and pointer-capture changes
(`disablePointerCaptureForcedLocked`, 7299) move a live pending entry back to
`mInboundQueue` without releasing it. Tests must distinguish live queue movement
from true release. A release bit on the exact entry, set only by
`releaseInboundEventLocked`, or a pending-and-inbound exact-membership check can
make that distinction.

## Allocator process-lifetime source bound

The pinned JNI `nativeInit` (2453-2469) has a static `std::once_flag`, fatally
rejects a second initialization, and explicitly retains `NativeInputManager`
for the lifetime of the process. That instance creates and owns one
`InputManager` (647-659). Thus a monotonic signed-63-bit counter owned by this
production dispatcher can be process-local and non-reused if it never wraps,
resets, or uses zero as authority. Test-only dispatcher recreation must not be
used as a production no-reuse proof.

## Policy drop and key parity

`dropInboundEventLocked` (1591-1643) does not silently leave native input state
stuck for a consumed key. It synthesizes `CANCEL_NON_POINTER_EVENTS` for the
raw `KeyEntry.displayId` and `deviceId` across all connections. `InputState`
creates fresh canceled key-UP entries from matching mementos (420-433), and
matching checks require device/display but do not restrict the key code unless
an explicit `options.keyCode` is present (606-625).

Consequently a bounded-map admission failure on a terminal UP can cancel all
other down non-pointer keys on that physical keyboard/raw-display cohort.
This is an explicit collateral-cancellation behavior, not native-state
stranding and not exact-pair-only cancellation. An ordinary hardware event
whose raw display is `INVALID` may share that cohort with earlier phone-target
keys from the same device. A different device is excluded by the stock
cancellation filter. Final review must preserve this distinction and test
terminal-UP/map-capacity parity without claiming unrelated same-device keys
are unaffected.

## JNI commit/exception boundary

The before-dispatch callback result and recycling of its Java KeyEvent copy
are distinct failure boundaries. A generic callback exception must not erase
some earlier admission record merely because the attempted call supplied the
same token. Java rollback must compare the exact record installed by that
invocation. Conversely, once Java successfully returns owned `-3`, a later
KeyEvent-copy recycle failure must either preserve the native pending
obligation or retire that successful exact record before converting to SKIP.
Otherwise Java committed authority remains ownerless.

`dispatchUnhandledKey` obtains another Java KeyEvent copy after native has
already taken the sole foreground completion obligation. If obtain returns
null with an exception pending, the exception must be cleared before calling
primitive Java completion. Calling `CallVoidMethod` while a JNI exception is
pending is not a reliable cleanup path. The same distinction applies to
callback exceptions before trying to recycle the copy. Tests must bind their
JNI ordering checks to the generated source and retain the exact-invocation
versus successful-commit distinction.

The exact provisional physical-pair decision is a separate obligation from
the delivery registry. In the SecurePaste branch, `beforeStock` can install an
APPLICATION PairToken before `maybeGrantAccess` runs. If the grant call throws,
no delivery record was committed and native drops the DOWN. Merely rolling
back registry records does not drain that provisional PairToken; a later exact
UP can then be routed to the app despite no DOWN having arrived. Stock
`InputState.trackKey` explicitly permits an inconsistent UP. Cancellation
synthesis cannot balance an initial DOWN that never created a native memento.
Invocation failure must therefore drain only its exact provisional
APPLICATION PairToken (identity compare), including failure before registry
publication. It must not drain a replacement occupant or unrelated stock
pair. Host exception coverage must include this initial-DOWN then terminal-UP
sequence, not only prove that a registry entry disappeared.

## Fresh flagged-entry control

Fresh native repeat/fallback/cancellation construction must initialize all
Wonad fields to `NONE`/zero; it must not copy an original admission marker.
That fact alone does not prove all fallback-flagged entries stay unadmitted:
the trusted injection path constructs a fresh entry using supplied KeyEvent
flags and runs private before-dispatch policy. If a fresh injected
`FLAG_FALLBACK` entry receives a new claimed token, the fallback-flag early
return in `afterKeyEventLockedInterruptable` must retire its exact owned
record. Taking FOREGROUND to TAKEN before that early return without running
completion would leak authority. Host coverage must exercise the fresh
flagged/injected corner, not only constructor non-copy assertions.

## Reentrant Java callback isolation

The private nonce authorizes the native invocation; copied public ID and
physical facts alone must not inherit that invocation's lineage. Every
`dispatchUnhandledKey` invocation therefore needs its own scope, including a
neutral stock/nonclaimed scope. A nested nonclaimed callback with equal public
ID, focus and physical facts must shadow an active outer claimed scope rather
than accidentally reuse it. It must likewise shadow the outer fallback scope,
and restore both scopes in exact finally order. Stock bypass and fallback
inheritance require the current invocation's trusted-claimed gate. Host
coverage must exercise nested stock equal-ID/equal-physical calls within both
outer unhandled and outer fallback scopes.

## Unchanged qualification boundary

The private post-target token/marker can preserve exact original lineage for
unhandled stock suppression. It does not itself prove raw queue origin,
device/display incarnation, hardware-chord isolation, or final-target
isolation. The earlier note's `INVALID_DISPLAY` F1-external to F2-phone raw
delivery gap remains open unless independently closed and tested.

Host projections establish source/protocol consistency only. Full native
compile and runtime qualification remain separate requirements.
