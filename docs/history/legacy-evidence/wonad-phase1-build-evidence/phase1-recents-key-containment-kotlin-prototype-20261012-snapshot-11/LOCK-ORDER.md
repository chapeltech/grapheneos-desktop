# Snapshot 11 bounded lock/order analysis

External source/host evidence only; no Android build or runtime qualification.

## Rejected predecessors

Snapshot 8 executed `Toast.show()` while the containment monitor was held:

```text
WMS lifecycle: WMS global -> containment monitor
input Escape:  containment monitor -> NMS toast queue -> WMS global
```

Snapshot 10 moved Toast but still executed `handleKeyGesture` under helper.
`IKeyGestureHandler` being `oneway` did not make a local Stub asynchronous. A
separate input-reader custom gesture can hold KGC's handler-record map and the
InputManagerGlobal local-handler map, enter PWM LAUNCH_APPLICATION, and reach
ATMS/WMS global:

```text
T1 lifecycle: WMS global -> containment monitor
T2 install:   containment monitor -> KGC handler records
T3 gesture:   KGC records -> local handler map -> PWM/ATMS -> WMS global
```

Snapshots 8-10 and their incorrect conclusions remain immutable history.

## Successor order

The helper monitor owns physical pairs, exact claim lineage, pure owner state,
and bounded action tickets. Install callbacks under it may only:

1. compare/set exact local `AtomicReference` and Boolean mirrors; and
2. call `Handler.post` once after reserving an action ticket.

They do not call KGC/PWM endpoints, Toast, Shell, or WMS. Handler capacity is
bounded by tickets retained through START and terminal dispatch; physical UP
does not release the ticket. Post rejection throws into monitored rollback
before action publication.

On KGC Handler, a Runnable briefly enters helper to commit/reject its ticket,
then releases helper before stock KGC/PWM. Retirement before commit drops
START. Commit before retirement is the admission point; later retirement
retains an exact cancellation obligation. Terminals are one-shot. PWM
identity-guards both APP_SWITCH preload and Alt-Tab visibility, so old cleanup
cannot affect a replacement endpoint.

Lifecycle cleanup under WMS global does local exact mirror cleanup and Handler
enqueue only. It never falls back to inline KGC. Each owner has at most one
cleanup obligation, bounded by `maximumActions`.

Claimed Escape never enters Shell QUIT. Exact target capture and eventual
close run under WMS global outside helper. The timeout Handler first obtains a
one-shot pure ticket, releases helper, then calls private WMS. Phone/unclaimed
Escape remains stock. Toast follows the same release-before-effect shape.

## Synchronous resolver limitation

The helper invokes an `OriginResolver` while synchronized. It releases the
WonadInputBridge private lock before reading current user, keyguard, lock-task,
display state, and `Settings.Secure`. Those reads may be synchronous and may
use Binder/provider locks; they are not claimed pure, nonblocking, or
Binder-free. Exact pinned AMS/UserController, ATMS/LockTask, display,
Settings/SettingsProvider/SettingsState, ActivityThread, UserManager, and
keyguard sources were reviewed. No synchronous edge from those reads back to
WMS global was found. This is bounded source evidence, not a dynamic or
whole-platform deadlock proof.

`Handler.post`/MessageQueue behavior is source-pinned. The queue lock does not
run the callback while held. Both Combined and Legacy queue implementations
and build selection are authenticated.

The custom-gesture/KGC/local-handler/PWM/ATMS chain that disproved snapshot 10
remains in the support ledger even though successor code does not enter it
under helper. The negative boundary is therefore reviewable.

## Remaining proof

- compile projected framework/Kotlin sources in a fresh platform build;
- run ordinary capture-keyboard fixtures on phone and claimed displays;
- exercise retirement, focus drift, token/window/task replacement, handler
  pressure, and claim replacement on a real system;
- retain lock contention/tracing evidence during those schedules.
