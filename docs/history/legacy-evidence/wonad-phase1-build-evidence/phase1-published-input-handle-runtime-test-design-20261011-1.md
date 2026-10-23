# Phase 1 published app-input handle runtime test design

Date: 2026-10-11

Status: design only. No production source, test source, OS stage, build, Docker
container, emulator, or guest was changed or started while preparing this note.

## Question this gate must answer

The host-compiled regression proves that a **newly populated** ordinary app
handle receives a narrowly owned `DROP_INPUT` when a sticky native display no
longer has a live lease. It does not prove what InputDispatcher does with an
already-published app handle between the exact lease deadline and application
of WMS's replacement input transaction.

The runtime gate must therefore inject a fresh pointer event in each of these
states on one fresh exact-image guest:

1. healthy live lease, as a delivery control;
2. expired lease while the old published app handle is still visible to
   InputDispatcher, before the exact WMS retirement call is forwarded;
3. after that exact call and after the dispatcher dump proves the replacement
   `DROP_INPUT`/OS-consumer state; and
4. after automatic recovery, as a no-stranding control.

The pass condition is exactly one target delivery in phases 1 and 4, and no
target or sibling delivery in phases 2 and 3. If phase 2 delivers, this is a
real temporal containment defect; a newly-populated-handle source test cannot
waive it.

## Why this should be a separate gate

The existing `frozen_client` gate already proves genuine ordinary-client
heartbeat expiry, three exact-black/OS-consumer observations, blocked keyboard
and mouse attempts, and automatic private-policy recovery. Its auditor also
deliberately rejects instrumentation and extra input. Changing that command
grammar would weaken a useful independent proof.

Add a separate gate, proposed name `input_expiry_transition`, reusing its
ordinary-client pause/incarnation and fixture parsing helpers but using a
separately authenticated, no-restart SystemUI test decorator. Current reviewed
inputs relevant to that integration are:

- `android/tools/native_frozen_client_smoke.py` —
  `fdc64254ed9f463b292453634a03a1fa883672c293e92e7468ae595dedef9ec3`;
- `android/tools/native_frozen_client_acceptance.py` —
  `7f4d82d9690c33384247b448d272f1bfb9bfe1280b9b57e17478aca026e315dd`;
- `android/tools/native_systemui_death_smoke.py` —
  `c3003aaa742ff9f0752c05795615a2f0e2ed677d89c8af7bc5abf2549145ca33`;
- `android/tools/native_shell_smoke.py` —
  `aa14565e02fedb608459703520d3d3258e1756828dcb3a9221eb7ba48aeb73b8`;
- `android/tools/run_native_matrix.py` —
  `64a578835f52a1c1dcdebcb406b316f25958adafecdc6c03cb3c3bf4df0218f2`;
- ordinary fixture `FixtureActivity.java` —
  `873cabb0202995e3ae75d13e7177fee95efc108c7987c7a8fa06541e290ee562`;
- broker `NativeDesktopController.kt` —
  `7a402bd3006a0e81df84df9e8ab737a49f7580fdb75adb92d8406659ea61eb6b`;
- `WonadUiBridge.kt` —
  `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`;
- final `WonadNativeBridge.kt` —
  `3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`.

## Deterministic test-only scheduler

Add a new instrumentation class to the existing platform-signed,
userdebug-only `transition-fault` APK. It should follow the already reviewed
`NativeCompletionProofInstrumentation` pattern:

- target the running `com.android.systemui` process without restarting it;
- require x86_64, userdebug, the exact Wonad fingerprint, a 128-bit run nonce,
  exact ordinary owner UID, generation, display id and display incarnation;
- reflect the actual `NativeDesktopController` and exact current `Session` on
  Shell's serial executor and retain that exact session object;
- install an identity-checked proxy only in
  `WindowManagerGlobal.sWindowManagerService`;
- forward and record every exact live
  `setWonadNativeUiLease(display, user, generation, expires, owner)` renewal
  for the selected display. Require its unchanged Binder result to be true,
  require `owner === retainedSession.asBinder()`, and retain the last successful
  `expires`; at retirement cross-check it equals the retained session's final
  `heartbeat + DesktopProtocol.CLIENT_TIMEOUT_MILLIS` (`5000 ms` in the
  reviewed SDK);
- forward every method unchanged except one call from the same Shell executor
  whose method and typed arguments are exactly
  `setWonadNativeUiLease(display, user, generation, 0, null)`;
- at that call, require `SystemClock.elapsedRealtime() >= deadline`, publish a
  typed `retirement_withheld` phase containing deadline, observed elapsed time,
  exact arguments, the retained renewal history, SystemUI PID/UID and a call
  count of one, then wait at most twenty seconds for an exact run-nonce release
  broadcast;
- on release, invoke the original Binder method once with the original argument
  objects, retain its boolean result and return/exception identity, publish
  `retirement_forwarded`, and return the unmodified result; and
- in `finally`, restore the cache only if it still contains this exact proxy,
  report exact restoration, and never overwrite a concurrent replacement.

This decorator delays only the real broker-to-WMS retirement call. It does not
change the lease deadline, generate a revocation, alter any input flag, inject
an input event, replace the ordinary client, or expose a production fault API.
It expands the real scheduling interval so the already-published handle can be
tested deterministically. The exact APK bytes, platform signer equality with
the selected image's SystemUI, manifest target/process/test-only fields, and
R8/no-restart isolation must be independently rechecked from raw tools.
The wait occurs on Shell's serial executor, never while holding WMS's global
lock. The decorator must prove the same controller Session object and IWM cache
delegate throughout its lifetime.

## Producer sequence

Use a fresh exact candidate container/boot and the same separate ordinary
Wonad and fixture UIDs as the existing expiry gate.

1. Establish one claimed monitor and two original fixture activities. Record
   exact boot/container/fingerprint, display incarnation/generation, process
   start ticks, task/activity/native identities, fixture counters and the full
   live `dumpsys input` inventory.
2. Inject one mouse tap at a point inside the selected target's exact native
   bounds. Require target `mouse_downs` and `pointer_downs` each increase by
   one, the sibling does not change, and the target remains the same
   Task/Activity/instance. This is the live-delivery control.
3. Start the authenticated decorator and require it to observe at least one
   successfully forwarded exact live renewal before its ready phase. Then pause
   only the exact ordinary Wonad PID, using UID, PID and `/proc/<pid>/stat`
   start-time checks. The decorator continues recording later live renewals, so
   the retirement phase binds the actual last successful WMS deadline rather
   than a racy host estimate. It must observe the genuine timeout-generated
   retirement call; the host must not call release or mutate the lease itself.
4. At `retirement_withheld`, read `/proc/uptime` (the guest
   `CLOCK_BOOTTIME` basis), `dumpsys input`, and fixture counters. Require the
   uptime lower bound is at or beyond the decorator's exact WMS renewal
   deadline. Authenticate an old active handle for the exact fixture component,
   UID, display, window name/token and application token: no `DROP_INPUT`,
   `DROP_INPUT_IF_OBSCURED`, `NOT_VISIBLE`, `NOT_TOUCHABLE`, or foreign `SPY`;
   no active inactive-Wonad consumer may yet substitute for it.
5. Inject exactly one fresh `input mouse -d DISPLAY tap X Y` at the same target
   point. Immediately reread fixture counters and `dumpsys input` while the
   decorator still reports the call withheld. Require the identical window and
   input-handle identity and active state on both sides of the tap and **no
   counter change in either fixture**.
   This is the previously unqualified already-published-handle assertion.
6. Send the one exact run-nonce release broadcast. Require the decorator's
   `retirement_forwarded` phase and original true result. Poll, for at most five
   seconds, until a raw dispatcher dump proves the target handle is inactive
   (`DROP_INPUT`, `NOT_VISIBLE`, or the existing strictly accepted equivalent)
   and the exact system-server-owned full-display Wonad inactive consumer is
   present. Capture the black monitor pixels using the existing inactive-frame
   parser.
7. Inject one more exact target tap. Require both fixtures' counters remain
   unchanged. Repeat the dispatcher/consumer and black-pixel observations so a
   summary boolean cannot replace the actual post-transaction state.
8. Require original SystemUI and system_server PIDs, ordinary client
   incarnation, fixture instances and tasks throughout. Release only the exact
   still-stopped client in `finally`; require automatic new generation/private
   policy recovery and exact proxy cleanup. Inject one final target tap and
   require one exclusive delivery, proving neither the test nor the new
   ownership bit stranded the app.

Every mutation/read must be retained in the existing canonical command trace.
Capture `/proc/uptime` around both expired taps and bind all raw dispatcher,
fixture, process, instrumentation and framebuffer outputs by size and SHA-256.

## Independent auditor requirements

Create a dedicated acceptance module rather than trusting producer booleans.
It should independently:

- authenticate the exact candidate image, boot, container, APKs, SystemUI
  signer, manifest and process identities;
- parse the instrumentation result/status stream and prove one ready, one
  withheld, one forwarded and one cleanup phase for the same nonce, session,
  deadline, call and SystemUI process;
- prove the actual heartbeat deadline had elapsed before the pre-forward tap;
- reparse the two bracketing pre-forward dispatcher dumps and reject a changed,
  already-dropped, foreign or ambiguous app handle;
- rederive fixture deltas from raw `dumpsys activity` output: live `+1/+1`,
  pre-forward `+0/+0`, post-DROP `+0/+0`, recovered `+1/+1`, with the sibling
  unchanged throughout;
- require the raw post-forward DROP/OS-consumer inventory and black pixels;
- require exact command order and exactly the four declared taps, one exact
  SIGSTOP/SIGCONT pair, one release broadcast, and no settings, topology,
  display, lease, service-restart or hidden repair command;
- reject a missing pre-forward state instead of treating the later DROP state
  as coverage; and
- re-audit exact-owned instrumentation/proxy cleanup and unchanged protected
  OS processes.

The result must be `not_passed` if the exact pre-forward interval was not
observed. A fast machine is not permission to silently skip this branch.

## Negative controls

The live and recovered `+1/+1` taps are mandatory runtime controls using the
same display, target point, input command and fixture counters. They prove a
zero expired delta is containment rather than a dead injector, off-window
coordinate, frozen fixture, or permanently disabled handle.

Focused host tests for the independent auditor must additionally mutate an
otherwise valid bundle so that:

- the pre-forward target counter increments;
- the pre-forward dump already contains `DROP_INPUT`;
- the tap falls before the deadline or after forwarding;
- the post-forward dump lacks the exact inactive consumer;
- the sibling receives either expired tap;
- the proxy call/arguments/result or deadline changes;
- an extra input, signal, broadcast or topology command appears; or
- proxy restoration, exact SIGCONT cleanup, or recovered delivery is omitted.

Every mutation must be rejected. As a classifier negative control, rerun the
auditor with a deliberately earlier cutoff inside the healthy live-control
interval; the known delivered live tap must then make the bundle fail rather
than be misclassified as contained input.

## Integration points

Proposed new files:

- `android/transition-fault/src/main/kotlin/org/wonad/desktop/transitionfault/NativeInputExpiryInstrumentation.kt`;
- `android/tools/native_input_expiry_transition_smoke.py`;
- `android/tools/native_input_expiry_transition_acceptance.py`;
- focused host tests for producer grammar, instrumentation scope and auditor
  mutations.

Add the exact instrumentation declaration to the transition-fault manifest,
then add the new gate to `run_native_matrix.py` with the existing fixture,
security and newly signed fault APK arguments. Add its independent semantic
auditor and exact scope to `native_backend_acceptance.py`, so full candidate
qualification cannot omit it. Rebuild and rebind the fault APK in the runtime
packet; do not reuse a prior packet hash after the manifest/classes change.
The 24-hour soak may consume the already-qualified result and need not run the
fault decorator repeatedly.

## Interpretation

This gate is intentionally capable of failing the current image. A failure in
phase 5 means the authority deadline can expire while InputDispatcher still
routes through an old ordinary-app handle. The narrow source correction for
new population is then insufficient; the repair must close the system-server
deadline-to-published-transaction interval (for example, by an OS-owned expiry
action/consumer), not merely add another APK-side poll or weaken this gate.
It tests a newly injected post-deadline pointer event; it makes no claim that an
event already routed before the deadline can be retroactively cancelled.
