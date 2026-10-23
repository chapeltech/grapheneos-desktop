# Snapshot 9 lock-order correction

This note is external host/source evidence only. It does not qualify an Android
build or runtime. Snapshot 8 and integration closure 1 are preserved unchanged;
their conclusion that the monitored Escape callback had no WMS-reaching path
was false.

## Confirmed snapshot-8 inversion

All paths below are from staged custom7 and are authenticated by
`apply_candidate.py`:

- `KeyGestureController` ran its Escape install callback while holding the
  `WonadPolicyKeyContainment` monitor and called `Toast.show()`.
- `Toast.java` (`f1da26d7d901315973e0364817576dbec6c1679eb6dbb11c7341fe27b0fd0120`),
  lines 198-229, synchronously calls `INotificationManager.enqueueToast`.
- `NotificationManagerService.java`
  (`7176bdfb9aac98688a5710569fd2af6384259b111c71b304f5caaa0faf2e5c86`),
  lines 4463-4493, holds `mToastQueue` and calls
  `WindowManagerInternal.addWindowToken`.
- `WindowManagerService.java`
  (`c2eb228520a585d86aa4097230f5c88700d32c08cbc8f2cf4da93b3787d6342c`),
  lines 3154-3161, acquires `mGlobalLock`.
- The Wonad UI lifecycle path runs under WMS state and synchronously publishes
  BLOCKED/RETIRED into the same containment monitor.

The cycle was therefore:

```text
WMS lifecycle: mGlobalLock -> containment monitor
input Escape:  containment monitor -> NMS mToastQueue -> mGlobalLock
```

## Snapshot-9 order

The monitored install callback still performs only the exact operations which
must be ordered with retirement: displaced-owner cancellation, stock START,
and delayed-message publication, with the existing compensating rollback.
`Toast` is absent from that callback.

After `installEscape` returns, Java calls
`commitEscapeDeferredEffect(owner)`. The helper briefly acquires its monitor,
checks exact owner identity, live non-draining physical pair, healthy exact
claim, and a one-shot pending bit, clears that bit, and returns a Boolean. It
does not invoke a callback or perform UI/Binder work. Java calls `Toast.show()`
only after that synchronized method has returned.

If blocking, retirement, replacement, pair drainage, or install rollback wins
before the commit, the permit is false and no Toast is published. If the commit
wins, it is the ordinary notification's admission point; lifecycle retirement
after that point does not revoke already-admitted UI work. This boundary does
not weaken the separate exact-owner authorization for the delayed Escape
action.

The hostile host schedule holds the install callback, starts exact claim
retirement and observes it blocked on the helper monitor, releases the callback,
lets retirement finish before the deferred commit, and proves the effect is
not published. Other controls cover one-shot, block, replacement, rollback,
and duplicate-install behavior. Source guards prove no `Toast.makeText` remains
inside the callback range and exact `install=true` plus owner commit precede
the sole generated Toast.

## Supporting source boundary

The generator also authenticates these reviewed sources used to bound the
remaining monitored callbacks/reads:

- `IStatusBar.aidl` `4a9e4910bfbdf05e22c5fe28dd59af5146daa102afd327a199b8b1b57baf3fa2`
- `StatusBarManagerService.java` `e7aef6f1795385937f1ad774740495ec3d8b0566fd328beb763d6a2f1b4c389a`
- `UserController.java` `b30cdcac2ca4976ab0f1427f468ad0d4e4e1de324a7fa76edcab81047dcaad41`
- `ActivityManagerService.java` `3851765b11595887e6b044af93646b3b859363195ce4a5ec19d50b7dc55a8dee`
- `ActivityTaskManagerService.java` `28d200431fd4a7289e3bf8f27d60f0c9472a8912da0211cf3bd5773eee170330`
- `LockTaskController.java` `929fb43d3bba2487a1ab9498be18b3fcea86bed8a1808d4034188dbce379d903`
- `DisplayManagerService.java` `4bcd0a935e70b9dfb692c892e749fc0fa295fb38660ea6c1310b0f6790422a5f`
- `KeyguardServiceDelegate.java` `522361e7cb37ffc9410a6879fd151260b7495504c4d8b8804a8bcfc2e722b74f`

No second concrete inverse was found in this bounded scan. That is not a
whole-platform dynamic lock-order proof; a platform compile and real runtime
campaign remain required.
