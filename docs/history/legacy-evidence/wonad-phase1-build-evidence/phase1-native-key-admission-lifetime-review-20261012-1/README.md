# Native claimed-key admission lifetime review (bounded, source-only)

Date: 2026-10-12

Status: review criteria, not an accepted implementation. The immutable
post-target snapshot 15 is rejected. The producer's native `EventEntry`
successor was still mutable when this note was written. No repository, staged
source, build, container, VM, or runtime guest was changed or run for this
review.

## Authenticated source scope

The paths below were read from the preserved custom-7 source tree
`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`:

| path | SHA-256 |
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

## Source facts

1. `createKeyEvent(const KeyEntry&)` copies the native `KeyEntry.id` into the
   Java `KeyEvent`; `android_view_KeyEvent_fromNative`/`KeyEvent.obtain` retain
   that integer. Exact Java copies also retain it.
2. The ID is not a production-unique nonce. `IdGenerator` contains only a
   30-bit CSPRNG value plus two source bits. `InputEvent.getId()` explicitly
   says collisions are possible and production logic must not rely on
   uniqueness.
3. A live `putIfAbsent(id, lineage)` can nevertheless use the ID as a bounded
   correlation index if a collision is rejected fail-closed and if stale or
   duplicate cleanup can never remove a later record with the same ID. It must
   not be described as globally unique.
4. Native synthetic repeat and both native fallback constructions allocate a
   fresh dispatcher ID. Exact Java copies retain an ID; modified Java events
   normally allocate a new ID.
5. A key is first offered to policy using focused token F1 while the dispatcher
   lock is released. The final foreground target is resolved later and may be
   F2. A Java map keyed by F1 or a current claim is therefore insufficient.
6. Key dispatch creates one foreground target plus zero or more non-foreground
   focus monitors. All entries share the same `KeyEntry`. Monitor finish or
   teardown must not consume or clean foreground authority.
7. The pending inbound reference is released immediately after dispatch queues
   are populated. The foreground `DispatchEntry` may remain in outbound or wait
   queues. Thus cleanup cannot be tied to ordinary inbound release after a
   successful foreground transfer.
8. Broken channels and input-channel removal drain outbound and wait queues
   through `releaseDispatchEntry`. A normal finish also releases the exact wait
   entry. Publish error, `WOULD_BLOCK` with an empty wait queue, and explicit
   removal converge on that drain path.
9. Policy unhandled/fallback is called with the dispatcher lock released. A
   channel can be drained while that call is in progress. Cleanup therefore
   needs a single atomic ownership transition, not two unconditional callbacks.
10. A foreground enqueue can fail before insertion: non-normal connection,
    inconsistent `InputState.trackKey`, or target failure. In those cases the
    authority must remain pending and be cleaned by inbound release.
11. `mKeyRepeatState.lastKeyEntry` can retain the original shared entry after
    its dispatch ends, but synthesized repeats construct a fresh `KeyEntry` and
    ID. A claimed marker must not be copied to the repeat.
12. `notifyKey` computes an `intendedDisplayId` for before-queue policy, but
    constructs the native `KeyEntry` using `args.displayId`. For an ordinary
    `INVALID_DISPLAY` hardware event, before-dispatch policy resolves the then
    focused display and rewrites only its temporary `KeyEvent`; final target
    lookup resolves `mFocusedDisplayId` again from the unchanged `KeyEntry`.
    An external F1 admission can therefore become raw delivery to a later
    phone/display F2 before unhandled processing. The marker can preserve stock
    suppression and original lineage, but it cannot by itself close this
    separately documented pre-target origin/target gap.

## Minimum acceptable private protocol

The private `-3` policy result may identify “claimed application admission,”
but it is not itself an exact admission token. A candidate needs an explicit
native ownership state on the exact `KeyEntry`, at least:

```
NONE -> PENDING -> FOREGROUND -> TAKEN
              \-> TAKEN  (pre-target/drop)
```

- Java installs the exact immutable `ClaimLineage` before returning `-3`.
  Live ID collision must reject the new event as consumed without replacing the
  existing record. Installation must be the final non-throwing action before
  the return, or have explicit rollback.
- JNI must decode `-3` before duration conversion. Unknown negative values
  (including `-4` and `LONG_MIN`) must fail closed and never become negative
  delay durations.
- The native `KeyEntry` becomes `PENDING`. Only successful enqueue of the one
  foreground `DispatchEntry`, after `trackKey`, may transfer it to
  `FOREGROUND`. Monitor entries never own or clean it.
- Inbound release atomically takes and cleans only `PENDING`. Foreground
  release atomically takes and cleans only `FOREGROUND`. Cleanup must be posted
  outside the dispatcher lock and must remove the Java record before any
  fallible diagnostics.
- Trusted unhandled processing must be gated by the native marker and obtain
  the original lineage, not a current claim. It may consume the record locally
  for the duration of fallback processing, but concurrent broken-channel
  release must not create a delayed duplicate cleanup capable of deleting a
  later same-ID record.
- F1-to-F2 re-resolution must retain the exact original lineage for stock
  suppression. Claim replacement, device/display reuse, or missing/mismatched
  lineage must fail closed; it must never authorize against replacement state.
- This post-target protocol must remain explicitly unqualified for raw F1-to-F2
  delivery while the native intended-display/incarnation check is absent. It
  must not claim that unhandled stock suppression also proves app-target
  isolation.
- Synthetic repeat, fallback, cancellation, monitor, and injected non-admitted
  entries start with `NONE` and cannot inherit a marker.

If the implementation stores only `CONTINUE_WONAD_CLAIMED` plus a boolean and
uses an unconditional `remove(id)`, it does not meet this protocol. Either an
exact native admission nonce must be carried end-to-end, or the implementation
must prove that the ID-indexed record has single-owner cleanup, collision
rejection, and no stale callback after reuse.

## Required hostile coverage

- simultaneous equal event IDs; completed-ID reuse; delayed duplicate cleanup
  after reuse; zero/reserved IDs;
- malformed policy returns `-4`, `LONG_MIN`, and unexpected positive delays;
- F1 policy admission followed by F2 target, claim A retirement/replacement B,
  display-ID reuse, and device-ID reuse;
- handled foreground, unhandled no-fallback, unhandled fallback, fallback UP,
  non-initial unhandled UP, and callback exception;
- no focus, stale/disabled/drop, connection non-normal, `trackKey` rejection,
  publish failure, pipe-full broken abort, channel removal, queue drain, reset,
  and target disappearance during the unlocked unhandled call;
- one foreground plus monitor sharing; the monitor finishes first and last;
- hardware repeat, synthesized repeat, Java-modified fallback, native fallback,
  cancellation entry, and injected event;
- claimed-capacity exhaustion remains isolated from phone/unclaimed input.

Passing host projections would establish only source/protocol consistency. A
full native compile and runtime execution remain required.
