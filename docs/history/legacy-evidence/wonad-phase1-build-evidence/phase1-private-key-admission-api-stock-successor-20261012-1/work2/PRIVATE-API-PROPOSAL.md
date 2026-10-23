# Private native admission-token slice: proposal before implementation

2026-10-12. External host/source proposal, not permission to stage or build.
Requirements authenticated from native lifetime review README SHA-256
`7e7105ef9e537cfb6abc7079e1ef06e01f612a8d7ecd81456ef7c77f62166650`.

The native dispatcher supplies a private nonzero monotonically allocated
signed-63-bit nonce to each exact `KeyEntry` policy invocation. A process-wide
atomic allocator never wraps/reuses; exhaustion supplies zero. Neither
`KeyEvent.id` (30-bit CSPRNG source ID) nor focus tokens are admission authority.
The nonce is passed through private dispatcher policy/JNI/IMS/KGC only, never
written into a public KeyEvent or delivered to an application.

Java computes pair/claim routing and completes SecurePaste/framework work first.
The final action before claimed `-3` is a bounded exact nonce-record insertion.
Duplicate/zero/exhausted/capacity failures drain claimed APPLICATION input;
phone/unclaimed input retains STOCK without requiring a nonce. An invocation
exception rolls back only the exact immutable record installed by that call.

The exact native entry has `NONE -> PENDING -> FOREGROUND -> TAKEN`, or
`PENDING -> TAKEN` on drop. Successful foreground enqueue after `trackKey` is
the only transfer; monitors neither take nor clean. Ordinary inbound release
marks the entry released and cleans only PENDING, never FOREGROUND. A reset
during the unlocked policy callback marks the exact entry released; returning
`-3` then takes/cleans the exact orphan registration instead of publishing a
new pending obligation. Moving the entry back to the inbound queue is not a
release and does not revoke it.

Foreground handled/unhandled processing atomically takes before an unlocked
callback. Foreground release sees TAKEN and cannot post a duplicate cleanup.
Primitive cleanup removes the Java record before fallible WMS diagnostics.
Unhandled scope uses original immutable lineage, fails fallback closed on
missing/mismatched records/targets, and exists only for the synchronous callback.
Fallback/repeat/cancellation/injected non-admitted entries start NONE. Unknown
negative JNI results fail closed before duration conversion; oversized positive
durations must not overflow.

Bounded-registry failure on a terminal UP is a POLICY drop, not a claim that
the native app DOWN is permanently stranded: stock dispatcher synthesizes
device/display-scoped canceled UP. This may cancel other tracked keys on that
device/display, and cancellation entries have no admission authority. The
collateral cancellation/fallback behavior remains explicitly unqualified.

This is only post-target stock-shortcut suppression/lifetime. Raw INVALID
display events can still be admitted at external F1 and delivered to phone F2
because `notifyKey` queues `args.displayId` instead of the policy's intended
display. Pretarget/final-target/device-incarnation/chord/runtime qualification
remain OPEN. No stock claimed Android UI endpoints are added.
