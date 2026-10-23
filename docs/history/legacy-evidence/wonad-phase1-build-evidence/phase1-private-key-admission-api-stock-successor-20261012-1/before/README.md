# Phase 1 private native admission-token successor

2026-10-12. Status: external-only, selected post-target source/host slice;
not integrated, not an Android build, not runtime/device qualification.

This successor was seeded from mutable-6 without editing that predecessor.
Its final frozen payload is `sealed-2/`; generated-attempts and host-attempts
outside that directory are preserved work evidence, not authoritative output.
Initial `sealed/` is preserved packaging-rejected history: its base/native
patches replayed correctly but added integration file diffs lacked new-file
mode headers. `sealed-2/` preserves identical implementation with those headers.
The parent repository, pinned custom-7 source, stages, SDKs, build/container
state, images, keys and userdata were not modified.

## Narrow implemented boundary

A private, nonzero, monotonically allocated signed-63-bit native nonce is tied
once to the exact KeyEntry; positive-delay retries retain that candidate.
The process-wide atomic allocator issues INT64_MAX once, then permanently zero.
The nonce crosses only private dispatcher-policy/JNI/IMS/KGC/completion wiring.
No public KeyEvent, app-facing SDK, Binder or wire field is added.
KeyEvent.id has only a collision-prone 30-bit CSPRNG value; it is bound
diagnostic evidence, never registry authority.

Java computes exact pair/immutable claim routing, performs SecurePaste and
other fallible work, then commits the bounded nonce record last before -3.
Only an accepted invocation-owned record can return -3. Duplicate/non--3/
exception rollback compares the exact own record, and drains only its exact
provisional PairToken. A duplicate call cannot remove or drain a replacement
record. Zero/exhaustion/capacity rejects claimed APPLICATION; ordinary
phone/unclaimed routes remain STOCK without requiring a token.

Native ownership is NONE -> PENDING -> one FOREGROUND -> TAKEN, or
PENDING -> TAKEN on drop. trackKey must succeed before the foreground transfer.
Monitors cannot take or clean authority. Ordinary inbound release cleans only
PENDING and marks exact real release. Reset/filter/disable during the unlocked
Java callback therefore cannot publish a new PENDING obligation onto an
already released entry; exact orphan cleanup runs outside mLock. A live move
back into the inbound queue is not release and remains eligible.

Handled/unhandled processing takes foreground ownership before unlocking.
Concurrent queue/channel drains see TAKEN and cannot post duplicate cleanup.
Pending/queue-abort/reset/recycle-failure cleanup carries a private abandoned
bit: it first removes the exact nonce record, then drains the exact retained
pair identity. Normal handled completion does not drain the balanced pair.
JNI primitive cleanup converts native nanoseconds to Java getDownTime millis.

Unhandled processing retains original immutable claim lineage, not current
claim or policy-time focus. F1-to-F2 completion suppresses stock for that exact
event; wrong display, missing lineage, retirement/replacement and reused
numeric display fail fallback closed. Each synchronous unhandled call shadows
outer scopes, including neutral STOCK calls. Matching requires exact Java
source/fallback object identity inside that invocation, not merely an equal
ID/physical tuple. finally restores reentrant scopes. Real KCM fallback scope
is created only after a real mapping; fallback does not obtain a second marker.

Synthetic repeat, native/Java fallback, cancellation and injected non-admitted
entries do not copy authority. A hostile trusted injected FALLBACK-bit event
which receives fresh admission still cleans its owner on the native early
return. Unknown negative JNI results (-4/LONG_MIN) fail closed before duration
conversion; positive delays above 60 seconds fail closed to bound conversion.

Claimed dedicated Android UI keys and the Tab pair of Alt+Tab are consumed.
Modifiers and ordinary Escape stay balanced application input; fixed Wonad
commands retain priority. No claimed stock Recents/All Apps/launcher/Caps action,
long-Escape Toast/QUIT/task-close endpoint, action queue or PWM owner is added.
Normal phone stock shortcut method bodies remain byte-equal to custom-7.

## Explicitly OPEN

This is not total input or app-target isolation. notifyKey uses intendedDisplayId
for queue policy but constructs KeyEntry with args.displayId. INVALID-display
hardware admitted under external F1 may therefore be raw-delivered to later
phone F2 before unhandled processing. The token only fixes post-target lifetime
and stock suppression. Pretarget queue-origin proof, final target/focus epoch,
physical device/generation/incarnation, device/display reuse, runtime and
physical-device acceptance remain unqualified.

KeyCombinationManager and SecurePaste retain their earlier source order.
Device-agnostic Power/Volume safety mixing and default-display effects remain
a separate OPEN chord-isolation obligation.

A bounded-registry failure on terminal UP is a stock POLICY drop. Pinned
InputDispatcher drops synthesize device/display-scoped canceled UPs; this is
not evidence that native permanently strands the earlier DOWN. The actual
stock InputState cancellation fragment is host-executed and cancels every
matching tracked key, including another key on that same device/display.
Cancellation entries start NONE and may follow stock cancellation/fallback
policy. Collateral cancellation/fallback and full phone isolation under this
failure are OPEN, not waived by the unrelated-device STOCK control.

Full native/framework compilation, actual JNI VM execution, actual queue
selection/publication, and Android runtime acceptance remain required.

## Preserved rejected history

Snapshot 14's six defects/seven schedules remain immutable:
initial-stock ordinary and system DOWN/claimed-UP, barrier DOWN/cleared-UP,
replacement drain overflow, focus-null DOWN/focused-UP, handled-history
saturation and null-KCM history saturation. The original pure routing fixture
is retained; nonce fixture exercises repeated handled/null-KCM completion,
focus/display history rejection, cap and pair failures.
Independent RED README SHA-256:
76c6b6e7aa76e71d0d4e3bb3ccaf52fa5c2e56874c4357a9bc0cc1181e13903f.

Snapshot 15 stale-focus authority and F1/F2 proof remain immutable:
review-1 README faa5dd7bb88f666edbf8d0fbb0296846e5ba9f9bccbdd4e687dbb78b5e8ed392;
review-2 README 669cb5c49d849733072a279ec74c4bb232ed3aeccd8fd36ede78fd04752b7f64.
The successor replaces historical focus/display permission with exact native
nonce ownership; it does not retract or qualify the raw F1/F2 delivery gap.

Required lifetime-review README:
7e7105ef9e537cfb6abc7079e1ef06e01f612a8d7ecd81456ef7c77f62166650.
PRIVATE-API-PROPOSAL.md was emitted before implementation. Implementation
precision: allocation is once per exact KeyEntry, not once per retry; each
Java invocation separately owns its compare-record rollback.

## Replay and payload

Run without staging/building anything:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-recents-key-containment-kotlin-prototype-20261012-7/sealed-2/test_candidate.py
```

Two Kotlin fixtures compile/run with pinned custom-7 Kotlin/JDK and 256/128 MiB
heap caps. A g++ C++20 projection compiles real extracted native admission,
release and after-key functions plus enqueue/stock-cancellation/JNI-decode
fragments against narrow Android stubs. Only the separate exhaustion allocator
copy changes initial storage from 1 to INT64_MAX-1. This is host/source
consistency, not a platform compile. Tests include hostile equal source IDs,
duplicate nonce/non-owning rollback, stale completion after ID reuse, zero/
exhaustion/cap, precommit SecurePaste failure, postcommit rollback, WMS failure,
neutral reentrant stock shadow, handled/unhandled/no-fallback/fallback-UP,
monitor first/last, release/reset during unlock versus live queue move,
trackKey/non-normal rejection, common publish/pipe-full/removal/drain release,
target disappearance during unhandled, injected fallback-bit cleanup, and
actual scoped cancellation collateral.

The sealed host directory contains generated source, Kotlin JARs, native
projection source/binary and replay output. MANIFEST.json binds their hashes,
authenticated originals/target union and compiler pins. Ordered payload:
01-frameworks-base-wonad-private-key-admission.patch;
02-frameworks-native-wonad-private-key-admission.patch;
03-wonad-input-integration.patch.
Base/native patches are against exact already-customized custom-7 inputs, not
bare manifest revisions. Integration patch is against pinned repository files
and adds two private helper sources; it is not a fourth Android project patch.
Current staging remains schema4/three projects until separately approved
native support. None of this payload is already in an image.
