# Lock and callback ordering review

The ordering domain is the monitor of the singleton
`WonadPolicyKeyContainment` instance. Physical-pair mutation, exact owner
installation, claim BLOCKED/RETIRED transition, delayed Escape authorization,
and saturation epoch reconciliation all linearize there.

## WMS lifecycle direction

`WonadUiBridge` is called under the WMS global lock. It invokes
`onUiClaimContainmentChanged` before publishing a closed barrier and
`onUiClaimRetiring` before unpublishing the exact shortcut claim. Each adapter
method evaluates `state.updateClaimStatus(...)` completely, releasing the
Kotlin synchronized monitor, before calling `publishCleanup(...)`.

The registered Java cleanup listener does not run stock cleanup in the WMS
callback. It posts `applyWonadPolicyCleanup(decision)` to the KGC handler. Thus
WMS-global-lock → helper-monitor is the only lifecycle lock edge; there is no
handler/gesture callback while both locks are held.

## Input installation direction

Installation deliberately invokes its small Java callback while holding the
helper monitor. This closes both retirement-before-publication and
publication-before-retirement races. On the pinned sources the callback can:

- compare/set exact atomic owner mirrors and stock booleans;
- aggregate exact displaced-owner cleanup;
- enqueue/remove KGC handler messages;
- deliver APP_SWITCH/Alt-Tab/Escape START or CANCEL through
  `handleKeyGesture`.

It does not call `WindowManagerInternal.getTopFocusedDisplayId`,
`WindowManagerService.withWonadGlobalLock`, or another WMS-global-lock method.
The exact-claim resolver used under the monitor reads volatile UiBridge claim
snapshots and containment sets, Binder liveness/deadline, active user,
keyguard policy state, lock-task state, DisplayManager state, and the secure
setting. The pinned WMS implementations of the two keyguard queries delegate
to policy rather than taking `mGlobalLock`.

`IKeyGestureHandler` is a pinned `oneway` AIDL. Shell/Launcher handlers are
therefore non-blocking remote delivery from system_server. The same-process
PhoneWindowManager registration handles APP_SWITCH and Alt-Tab through
`preloadRecentApps`, `showRecentApps`, and `hideRecentApps`; those exact paths
call `StatusBarManagerInternal` and do not acquire the WMS global lock. Meta and
Caps installation publish only Java mirrors; their stock actions occur on UP
after helper completion. The same bounded categories cover compensating
rollback and displaced-owner cleanup.

Consequently the pinned graph has no helper-monitor → WMS-global-lock edge,
and a lifecycle thread waiting for an in-flight owner installation cannot form
a cycle. The source-map pins the AIDL, InputManagerGlobal, WMS, PWM, Shell,
Launcher, adapter, and generated KGC bytes. Any future change to registration,
resolver reads, gesture handlers, or callback bodies invalidates this review
and requires a fresh lock-order audit.

## Failure ordering

The helper removes a failed new owner under the same monitor. Its Java
rollback always attempts displaced-owner cleanup and new-owner compensation;
each cleanup attempts Meta, Caps, Alt-Tab, APP_SWITCH, and every Escape owner,
preserving the original callback exception as primary and later failures as
suppressed. Eventless lifecycle cleanup is posted in exact helper order. Java
atomic identity prevents an old queued cleanup from clearing a replacement.

This is a source review and bounded host composition result, not a platform
deadlock test or device runtime result.

