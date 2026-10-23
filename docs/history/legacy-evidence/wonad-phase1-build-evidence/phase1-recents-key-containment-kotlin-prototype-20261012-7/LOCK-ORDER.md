# Selected post-target lifetime and lock review

External host/source scope only. No platform lock/runtime qualification.

Pure containment helper methods own bounded pair/identity state and never call
WMS, Settings, JNI, Binder, Handler, KGC, PWM, Toast or task-close code.
Routing captures exact origins/lifecycle epoch under the helper monitor,
performs fallible observations outside it, then commits immutable observations.
WMS lifecycle may publish BLOCKED/RETIRED into the pure helper; no reverse
helper-to-WMS callback exists.

deliveryLock protects only the bounded private-nonce registry. Record creation
and framework work precede publication. Removal precedes target/WMS reads or
diagnostics. Pair-abandonment runs after deliveryLock is released and compares
the exact retained PairToken. AdmissionCall rollback removes only its own
record by identity, then drains only its provisional pair; reentrant calls
restore previous invocation state.

All KeyEntry PENDING/FOREGROUND/TAKEN transitions occur under InputDispatcher
mLock. The process nonce allocator is atomic; per-entry candidate assignment
is under mLock and persists across delay retries. Real inbound release sets
wonadInboundReleased. Moves back to inboundQueue do not. The unlocked policy
return checks that release marker before publishing PENDING and cleans an
orphan outside mLock.

Successful trackKey and foreground enqueue transfer one pending obligation.
Monitor entries never own it. Ordinary inbound release after transfer does not
clean foreground authority. Foreground completion takes before unlocking for
Java; broken/removal/outbound/wait drains can then observe only TAKEN. Pending
and aborted foreground releases post cleanup outside mLock. The posted callback
uses exact private nonce and bound public facts, never KeyEvent.id as authority.

Every unhandled invocation pushes a scope, including neutral STOCK invocations.
It temporarily shadows both outer unhandled and fallback scopes. Exact Java
event reference plus current invocation marker is required; public fact
collisions cannot inherit outer authority. finally restores the prior stack.
Fallback scope is pushed only after KCM returns a real mapping. It carries old
immutable claim lineage and cannot obtain another native token.

The census recovery captures mutation epoch, performs complete trusted native
all-device/all-keycode UP reads outside the helper, then commits only an
unchanged epoch. This is exceptional device-scoped fail-black recovery, not
physical-device/incarnation qualification.

No queued stock action or private desktop UI endpoint exists in this slice.
Pretarget PWM, raw INVALID-display F1/F2 target re-resolution, device/chord
isolation, and collateral device/display cancellation/fallback remain OPEN.
