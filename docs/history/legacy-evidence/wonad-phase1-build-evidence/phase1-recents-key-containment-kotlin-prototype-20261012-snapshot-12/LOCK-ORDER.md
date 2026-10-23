# Snapshot 12 bounded lock/order analysis

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

1. compare/set exact local `AtomicReference` and Boolean mirrors.

They do not call Handler, KGC/PWM endpoints, Toast, Shell, or WMS. Claimed
action capacity is bounded by tickets retained through exact terminal cleanup;
physical UP does not release a ticket while lifecycle cleanup remains due.
Phone/unclaimed stock state is not charged to that capacity.

On the input thread, `mWonadPolicyActionLock` briefly enters helper to
commit/reject a ticket, then releases helper before stock KGC/PWM. The lock is
held through endpoint delivery acknowledgement and STARTED/FAILED recording.
Phone and claimed Wonad actions use the same domain. Retirement before commit
drops START. Commit before retirement is the admission point; later retirement
retains an exact cancellation obligation. Terminals are one-shot.

PWM uses a separate `mWonadRecentsEndpointLock`. All five state-and-delivery
mutations—preload, cancel, toggle, show, hide—take it. A claimed START carries
an exact reservation in a companion endpoint-reservation domain. Under the
PWM lock it either consumes that still-current reservation and performs state
plus the one-way SystemUI send, or returns without mutation. Direct stock
mutations invalidate the reservation first. KGC receives a per-dispatch
delivery acknowledgement and records STARTED only when PWM applied it.

The acquisition direction is:

```text
Wonad input: KGC action lock -> KGC records/local handler map
                           -> PWM endpoint lock -> reservation lock
direct PWM:                 PWM endpoint lock -> reservation lock
```

The PWM endpoint domain never calls helper lifecycle state, KGC, or the action
lock. StatusBarManagerService forwards preload/cancel/toggle/show/hide and the
show-path keyboard-shortcut dismissal to remote one-way `IStatusBar`; the
endpoint monitor is therefore held through ordered delivery without a
synchronous WMS/KGC re-entry in the reviewed chain. PWM identity-guards both
APP_SWITCH preload and Alt-Tab visibility, so old cleanup cannot affect a
replacement endpoint.

Lifecycle cleanup under WMS global does local exact mirror cleanup and one
Handler enqueue only. It never takes the action/PWM endpoint locks or falls
back to inline KGC. Each claimed owner has at most one cleanup obligation,
bounded by `maximumActions`. Handler-post rejection retains that exact
obligation and leaves the subsystem fail-black; surrounding WMS cleanup may
aggregate the exception rather than abort its transaction.

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
