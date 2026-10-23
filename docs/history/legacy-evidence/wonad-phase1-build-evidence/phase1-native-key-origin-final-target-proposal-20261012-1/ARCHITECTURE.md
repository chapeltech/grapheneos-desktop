# Native initial-origin/final-target proposal: early architecture

2026-10-12. External-only proposal, before implementation. No permission to
stage, build, run or qualify any platform. The preceding private admission
seam/STOCK repair is separate; sealed predecessors remain unchanged.

## Required boundary

An exact physical initial DOWN first receives a private immutable native origin
packet and an exact per-pair route receipt. STOCK receipts preserve the entire
existing native phone/unclaimed route, including focus migration. A Wonad
receipt preserves original immutable claim lineage and constrains actual
delivery to the exact originally admitted native target. A later numeric
display/window/device slot or current claim cannot replace that receipt.

Do not globally change KeyEntry.displayId from args.displayId to the queue's
intended display. That would change stock migration semantics. Capture the
queue's native intended display separately as immutable evidence, never as a
mutable routing cache or guessed Java top focus.

## Origin and receipt

NotifyKeyArgs currently carries only public-like device/source/key/time/display
facts, not InputReader physical incarnation. Reader must mint a nonzero,
non-reused signed63 InputDevice lifetime token and carry it directly with a
private subdevice/mapper incarnation and physical-pair token/reset epoch
through ordinary key and canceled-UP
notifications. The 32-bit mutable InputDevice generation is diagnostic only.

InputReader.loopOnce appends NotifyInputDevicesChanged after keys produced in
the same batch. Thus consulting dispatcher's current mInputDevices generation
at notifyKey is not a reliable join, even before considering ID reuse.
InputDevice.reset builds mapper cancellation UPs before notifyReset; they need
old pair provenance while future DOWNs receive the new reset epoch. Delayed
keys/reset/removal must name the exact reader lifetime, never only deviceId.

There is a stronger batching hazard: processEventsLocked accumulates keys in
a local list, while add/remove paths append lifecycle/reset args directly to
mPendingArgs, which is then concatenated before those keys. A raw batch such as
DOWN(old), REMOVE, ADD, DOWN(new) can deliver retirement/reset before BOTH key
args, including the pre-removal DOWN. Ordinary notify FIFO is not raw-production
ordering. Required provenance carries a capture-time production/retirement
serial so an old claimed event cannot become a new lifetime's event; existing
STOCK notification order must not be globally rewritten to hide this issue.

Private origin must also round-trip the native InputFilter AIDL/Rust/callback
pipeline. A C++ field alone is lost. SlowKeys mutates public downTime and holds
pending keys by numeric device/scan; immutable physical downTime and pair nonce
must survive the delay, and exact reset/retirement must drain pending Rust keys
before they can cross re-add. TRUSTED/FILTERED flags are not reader provenance.

Initial origin classification is a private, read-only policy call over this
exact native packet and captured native queue display/focus/window evidence.
It returns an invocation-owned per-pair receipt: STOCK, immutable Wonad claim
lineage, or fail-closed DRAIN. It must not perform stock actions. This explicit
receipt is needed before later raw INVALID display resolution: a guard that
runs only after -3 cannot stop a claimed queue-origin event being reclassified
STOCK on a later phone target before it ever produces -3.

Compatible EventHub endpoints can merge into one InputDevice and keyboard
mappers share its source. Thus a device lifetime plus source/scan/time is not a
physical-pair identity: each InputDeviceContext/mapper needs its own private
incarnation, and a first-DOWN pair nonce retained in that mapper's KeyDown.
Subdevice retirement must emit exact outstanding-pair provenance before the
mapper is erased; current removal-before-reset ordering can lose its KeyDown
cancellation. This is a required lifecycle change, not an inferred device map.

Native history binds {reader lifetime, subdevice/mapper incarnation, pair nonce,
reset epoch}; source/scanCode/native downTimeNs/output keyCode are bound evidence,
not pair authority.
Multiple devices and physical slots remain independent. UP/repeats inherit
only that exact immutable pair receipt. Missing/mismatched/replaced pair
provenance cannot adopt a current claim. A same physical-slot new DOWN abandons
the old pair by identity; its later UP cannot remove or cancel the replacement.
Equal public facts from different mapper incarnations are not a same physical
slot: they require independent simultaneous history, not mutual cancellation.

Injected/filtered events are a distinct native provenance domain. They cannot
join hardware history using public device/key/ID/time facts. Stock injection
semantics remain unchanged; a supported claimed injection path requires its
own trusted private origin/principal receipt. Otherwise claimed injection is
fail-closed, not inferred hardware authority. No public SDK/KeyEvent field is
added and exact public copies carry no receipt.

## Claimed-only final target gate

Before the Java policy unlock, capture exact native target evidence:
logical display, WindowInfo.id, strong binder token and strong Connection
identity, plus native focus/lifecycle serial. WindowInfoHandle pointer alone
is insufficient: updateWindowHandlesForDisplayLocked deliberately reuses and
mutates handles by window ID. An authoritative native focus serial must change
on every real focus transition; F1 -> F2 -> F1 cannot silently restore a stale
admission. Native display/channel teardown also revokes the exact fingerprint.

After policy returns and on every pending/paused/key-wait/focus retry, a claimed
receipt must match that exact target. Check again after actual focused-window
resolution and before successful foreground trackKey/enqueue. Neither a
replacement window nor a phone display can take the event. No monitor can own
or refresh the target constraint. A non-claimed/STOCK branch executes unchanged
stock code and does not consult the claimed constraint.

Derived fallback/cancellation/repeat entries start with admission NONE and no
copied nonce. Where needed, a separate immutable routing-only constraint may
restrict delivery to the original exact target; it grants no Java policy/app
admission authority. Claim retirement/replacement cannot refresh it.

## Abandonment and bounded history

Abandonment is exact-pair and exact-original-connection scoped. Stock POLICY
drop's device/display-wide cancellation is insufficient: it can cancel another
key on that same device/display. The proposed private InputState memento tag
and CancellationOptions selector identify only the original native pair
identity, with source/device/key/downTime as bound corruption checks. A new
same-slot pair, another device, monitor or unrelated STOCK key is untouched.
Fallback state for claimed pairs must likewise be pair-tagged rather than
borrowing InputState's existing keyCode-only fallback map.

No cancellation is retargeted via current focus. Missing/broken original
connection means abandon without delivery to a replacement. A canceled-UP is
sent only for an exact recorded delivered DOWN; no invented terminal for an
unpublished initial DOWN. Terminal/reset/remove/filter/dispatch-disable/error
paths retire the exact receipt once outside native locks. Pair history lives
until a real terminal/reset/removal, not ordinary inbound release after DOWN.
Exhaustion/drain is device/lifetime scoped; it cannot suppress unrelated phone
input. Capacity recovery needs explicit exact-lifetime all-UP evidence, not
timeouts or global numeric-device guesses.

Existing per-key getKeyCodeState calls each acquire the reader lock separately;
helper mutationEpoch does not observe a new reader DOWN still queued before
policy. Recovery therefore requires a private atomic exact-pair reader census,
reader activity sequence and source-ordered fence through delayed filters,
dispatcher and policy. Commit requires no pending/inflight origin at or before
the cutoff and a acknowledged fence; later DOWNs are processed under the new
epoch. If this cannot be proven, quarantine is not released early. A host
allKeysReleased Boolean is not an atomic native census proof.

## Planned executable controls and remaining requirements

Source-authenticate immutable before bytes. Compile generated actual-method
projections for native notifyKey/injection/getTargetDisplayId/final target
resolution, policy-unlock/return, enqueue and scoped InputState cancellation.
Compare stock control and proposed stock branch side-by-side under queue/policy
focus migrations, null focus, retries, DOWN/UP and multi-device schedules.
Hostile claimed cases include INVALID F1-external -> F2-phone, same-display
window replacement, F1 -> F2 -> F1, channel/display recreation, reset during
policy unlock, old UP after same-slot new DOWN, delayed reader lifetime reuse,
bounded capacity, target disappearance and cancellation collateral controls.

This architecture requires real private reader provenance and the per-pair
policy receipt protocol. A native target-only projection is not the complete
implementation and must keep those missing prerequisites OPEN. Pretarget PWM
actions, safety-chord isolation, full native/framework build, VM/JNI and actual
physical-device runtime acceptance are not waived by host controls.
