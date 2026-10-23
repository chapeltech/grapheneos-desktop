# Bounded review: published app-input expiry investigation

Date: 2026-10-11. Observations completed at approximately 13:30 UTC.

Scope: read-only, named-file source review of the proposed runtime design and
the staged custom-7 input paths. Only this separate review note was written.
No stage, production source, test source, compiler, build, Docker container,
vendor workflow, emulator or guest was changed or started. This is not a runtime
result, complete source-freeze proof, or OS qualification.

## Verdict

Revision 1 does not supply its claimed deterministic scheduling interval.
Delaying the genuine SystemUI retirement call does not delay WMS's independent
lease watchdog, nor any other InputMonitor repopulation. A correct image can
already have published containment before the proposed pre-forward tap. An
absent old admitted handle is unavailable transition-state coverage, not a
product defect; it also cannot count as proof of the old-handle assertion.

There is no reviewed, presently available SystemUI-only mechanism that forces
that old-handle interval while leaving WMS, its watchdog, and real publication
unmodified. Real post-containment input denial and healthy/recovered delivery
controls remain valid bounded integration assertions. A natural-deadline probe
can search for counterexamples without freezing WMS, but is opportunistic and
does not establish a universal instantaneous-deadline property.

The literal API-v3 paragraph defines authority timeout and the effects of
revocation. It does not define an eventTime/dispatch-time linearization point,
atomic compositor deadline, or immediate motion-targeting check. Do not claim
that wording or the existing transactional checks proves such a stronger
property. Equally, do not invent a latency allowance: 250 ms is poll cadence,
not a permitted grace period. An explicit stronger release policy would be a
separate normative decision, not a finding from this source review.

## Exact independent expiry and publication paths

Workspace paths below are relative to `/u/elric/tree/wonad/android`. Platform
paths are relative to the current checkout
`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`.

1. **Logical UI authority is checked against current elapsed realtime.**
   `WonadUiBridge.kt:235-243` resolves an exact live owner and calls
   `InputNative.uiMode(..., SystemClock.elapsedRealtime(), ...)`.
   `broker-rust/src/external_ui.rs:105-127` changes the owned lease to Blank
   when `now >= expires`, environment/user checks fail, or the clock fails.
   This Rust method is evaluated on calls; it is not an autonomous timer.
   JNI `input-jni/src/lib.rs:48-64` serializes it and returns fail-blank on
   mutex failure. A null nativeLease immediately denies new native mutations
   and new app-handle population, but does not itself publish a SurfaceFlinger
   transaction.
2. **WMS independently polls each exact claim.**
   `WonadUiBridge.kt:345-366` constructs a `wm.mH` Runnable which takes the WM
   global lock, clears its scheduled bit, reconciles only the exact current
   claim, and reschedules itself after 250 ms while that claim exists.
   Setup/renewal invokes `schedulePoll(..., 0)` at line 380; lines 427-432
   avoid duplicate posts. An already queued poll is not rescheduled to the
   heartbeat deadline by renewal. The cadence is relative to completion and
   handler scheduling; it is not a maximum observed latency.
3. **That poll does not need SystemUI retirement.**
   `WonadUiBridge.kt:452-469` calls `uiMode` with current time and environment.
   An expired mode or dead owner calls `containAndRelease` directly.
   Lines 789-810 first publish the blank volatile barrier, retire keyboard
   authority and fixed shell/observer planes, and prepare the real full-screen
   OS input consumer. Lines 813-839 hide ordinary tasks, reconcile focus and
   schedule animation. Lines 844-847 park Rust UI authority and unlink the
   owner after attempted framework containment. This runs independently of
   the Shell/SystemUI executor on which the proposed decorator waits.
4. **The broker is another, separate retirement source.**
   `WonadController.kt:85-89,141` reconciles on Shell's executor every 500 ms.
   Task/display/user/protected-state listeners also reconcile at lines
   232-257; session calls and pending-operation polling reconcile too.
   `NativeDesktopController.kt:232-236` asks Rust to reconcile current
   authority; `native_authority.rs:140-163,208-210` rejects heartbeat age
   outside `[0, CLIENT_TIMEOUT_MILLIS)`. Broker revoke clears `session` before
   its cleanup list (`NativeDesktopController.kt:308-327`), then calls real
   `setWonadNativeUiLease(..., 0, null)`. The retained Session object can be
   authenticated during that call, but it is no longer the controller's
   current session. WMS accepts exact old-generation 0/null retirement and
   parks it idempotently (`WonadUiBridge.kt:299-304`); a true return does not
   prove WMS had remained live until the call.
5. **Input population is independently expiry-aware.**
   `InputMonitor.java:337` applies `WonadNativeBridge.configureInput` after
   stock computation. NativeBridge lines 1449-1455 route ordinary app windows
   to clipping; lines 1489-1494 independently recheck nativeLease and add
   narrowly owned DROP_INPUT when there is no lease. Any later population can
   therefore replace an admitted handle even while broker retirement is held.
   This fixes newly populated handles, not the already-published deadline
   interval by itself.
6. **Publication is transactional and asynchronous.**
   `InputMonitor.java:117-150,344-373` schedules population on WMS's animation
   handler under the global lock, or merges a synchronous population into the
   caller's transaction. Lines 608-614 merge ordinary population into the
   display's pending transaction and schedule animation. Lines 671-687 apply
   changed handle information to actual window surfaces.
   `WonadUiBridge.kt:756-767` publishes the OS consumer through the pending
   transaction; a private boolean alone is not native motion containment.
   `WindowAnimator.java:170-188,279-290` merges/applies display transactions.
   `InputDispatcher.cpp:7373-7407` processes actual WindowInfosUpdate lists
   under its lock, replaces per-display windows and wakes dispatch.

Consequently, holding one SystemUI Binder invocation expands only that
invocation's scheduling interval. It does not expand the precise interval
between UI deadline and dispatcher containment. WMS can independently finish
the state transition, including actual consumer publication, while it waits.

## Event-time boundary actually present in the reviewed code

`WonadInputBridge.kt:237-267` checks published barriers and a live deadline
without WM's global lock, but its interface accepts a KeyEvent. Its pinned
integration is `KeyGestureController.java:615-665`. It is not a motion filter.

Pinned motion policy in
`services/core/jni/com_android_server_input_InputManagerService.cpp:2015-2049`
sets PASS_TO_USER and returns for injected/untrusted motion on an interactive
display, and separately for ordinary interactive motion, without entering a
Wonad Java deadline check. `InputDispatcher.cpp:5025-5046` invokes this policy
for injected motion. Pointer targeting uses the current installed WindowInfo
list (`1514-1529,2175-2225`), then checks current visibility, touchability,
occlusion, channel/connection state and DROP flags (`5584-5624,7410-7424`).
`libs/gui/include/gui/WindowInfo.h:195-260` has no Wonad authority deadline.

These paths explain why a still-admitted published app handle is not
independently expired merely by advancing the UI-lease clock. They establish
a structural gap relative to an *additional immediate pointer-admission
requirement*, not observed delivery, interval length, or an existing API-v3
contract violation. No timing guarantee was measured in this review.

## Sound bounded test scope without production changes

- Keep the established frozen-client gate separate. Authenticate fresh image,
  exact client UID/PID/start ticks, display incarnation/generation and original
  fixture/window/task identities; pause only the exact ordinary client and
  resume it in finally. Do not alter real deadlines or protected OS processes.
- Observe real DROP/consumer publication before testing deterministic
  post-containment denial. Require unchanged fixtures and healthy/recovered
  positive controls; retain raw state, input commands and counter deltas.
  This proves actual transactional containment, not instantaneous deadline
  enforcement.
- If searching the natural deadline interval, retain the exact last successful
  WMS renewal deadline and uniquely identify each fresh event, its source,
  coordinates, guest enqueue-time bounds and actual fixture delivery. Use
  bounded, reviewed test-only instrumentation/fixture changes in a future
  separately bound packet; no production fault API or watchdog delay.
- A delivered fresh event proven to have been injected after the final
  deadline is a confirmed deadline-delivery observation. An app callback
  occurring after deadline for a previously routed event is not such evidence.
  Classifying the former as a release-contract violation requires an explicit
  policy adopting immediate pointer admission as the normative boundary.
- No observed old handle means coverage unavailable. No delivery in valid
  sampled schedules means sampled no-delivery evidence. Neither proves the
  natural interval cannot exist. A required but unobserved stronger test can
  remain unqualified without being reported as a product failure.

Two matching dispatcher dumps only show matching samples, not continuous
installation during the event. The dispatcher dump prints recent event
descriptions/ages (`InputDispatcher.cpp:6315-6393`), but is not a per-event
target/publication timeline. `mWindowInfosVsyncId` is maintained on actual
updates but is not exposed by that dump as an atomic bracket.

The pinned `android.window.WindowInfosListener` and TestApi wrapper are
read-only SurfaceFlinger observation interfaces. They do not prevent an
independent WMS transaction and their callbacks are not by themselves an
InputDispatcher target-selection acknowledgment. The TestApi wrapper also
omits raw DROP_INPUT in its public WindowInfo view. They may improve sampled
evidence, not create the missing deterministic hold. No reviewed listener or
SystemUI Binder decorator closes all independent publication routes.

Clock bases must remain explicit: the lease uses elapsedRealtime/boottime;
`InputShellCommand.java:482-492` creates tap MotionEvents using uptimeMillis.
The two values cannot simply be numerically compared across suspend. A guest
boottime lower bound before constructing/injecting a fresh event can establish
that attempt occurred after the lease deadline, but cannot turn a fixture
callback timestamp or supplied eventTime into the dispatcher linearization
point. `/proc/uptime` is coarse independent bracketing, not an atomic dispatch
record. The command's motion injection uses WAIT_FOR_FINISH; that alone does
not make two raw window dumps a continuous state history.

## Design identities and reviewed successor

Revision 1 SHA-256:
`9489af2c2b1c4948c972af03105687b9c6a2099a6c784bf4edbda3462a43f8ac`.

The author prepared a separate revision 2 during review, preserving revision 1.
Its final reviewed SHA-256 is
`68cb7f93a9a7bfd970d14a6c1477ac22b283d7c5bd0a0502f472a496ad0d954d`.
It corrects watchdog/repopulation independence, unavailable-coverage
classification, clock/dump limitations and the unresolved normative dispatch
boundary. This reviewer accepts those bounded design corrections, not a
runtime mechanism, mandatory new matrix gate, or qualification result.

## Input identities

All eight named Wonad source files below independently matched both workspace
bytes and the custom-7 stage marker. Stage marker SHA-256:
`5fb1f000c37ab702bbd2722d4dde6d1936d792533d2e76798e8ce59e271c0d5d`.
Frameworks/base pinned commit: `84183aff99be5e156dc0446a6fa2d4a7150f4bc3`.
Frameworks/native pinned commit: `1c83ac6ae533c74ecb0486369c0d2f9e79783b3d`.
No source-wide inventory or tracked check was repeated.

| Named input | SHA-256 |
| --- | --- |
| WonadNativeBridge.kt | `3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c` |
| WonadUiBridge.kt | `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4` |
| NativeDesktopController.kt | `7a402bd3006a0e81df84df9e8ab737a49f7580fdb75adb92d8406659ea61eb6b` |
| WonadInputBridge.kt | `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff` |
| WonadController.kt | `7fdb6ed431aca0266d0b1b7a8cd6fe33c953fdae37b1b9b1914c636a67242e5d` |
| broker-rust/src/external_ui.rs | `3cf6defb8756a438dd28e52ec57c1ebadd47797d829be77c6a680e99de52923c` |
| broker-rust/src/native_authority.rs | `84c69c5564cb418aad6a428e690706bacb9e437d40c90abbe7093305eef9fd31` |
| input-jni/src/lib.rs | `14641b2e4e099c8bc8b18002597b4e3b704cf01ca8a787e1a3b50ce6b6a5268c` |
| desktop-sdk/API-v3.md | `c4346a29317f6cf58a5549fb199c7d97aec437c31a5ece85525b3141f879daf5` |
| desktop-sdk DesktopProtocol.kt | `67a33a5116ee5e9e51df3e7cb9c51f8c34976d4d0ee091b2fc881342513618dc` |
| InputMonitor.java | `bdb799f17556ffad88f3165f9993b08768999db94e13efb12cb919d39b2d7734` |
| WindowAnimator.java | `96ed78bacd983b4bca43925a20055d8e63726a70c03ad621d44d52a8d34a7d67` |
| KeyGestureController.java | `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5` |
| InputShellCommand.java | `9b2c7d34d4f823b65e5b024e6b0ca124fae860c41a47bfa5c59d25af9d2ed5b8` |
| com_android_server_input_InputManagerService.cpp | `0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5` |
| InputDispatcher.cpp | `4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9` |
| libs/gui/include/gui/WindowInfo.h | `c5b2543f2c36d2edfc1dbe65f3b34bc27aa4736ddd6e0bcd4b04be81564befbb` |
| android/window/WindowInfosListener.java | `c60d33a2806fa489580983d8ac6fd87e535f41a027ae3a9c83b67d74937d24ce` |
| android/window/WindowInfosListenerForTest.java | `61e3f783d45eaa0e750ee649119c6f8a18a74b606f2997bfe3f15401e0af0068` |

No new latency allowance, dispatch contract, mandatory test gate, runtime
defect verdict or source mutation is authorized by this note.
