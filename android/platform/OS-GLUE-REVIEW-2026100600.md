# Phase 1 privileged OS-glue review — GrapheneOS 2026100600

Date: 2026-10-13; historical checkpoints below retain their original dates.

> Historical source-review record: the deployment target is now Pixel 10
> (`frankel`). Earlier Frankel/Shiba paths and observations retain their original
> scope; neither old device artifacts nor emulator results qualify the new phone.

## Supervised emulator review addendum — 2026-10-19

This bounded source-review addendum covers the immutable development image
`sha256:3e977b15b3f0093506c95bf785d5ec7e2c9d6642e2afe49c51d592975c1deb47`.
The [59-file owned-source and 50-patch/76-target inventory](PHASE0-OS-INTERFACES.md#supervised-emulator-source-inventory--2026-10-19)
and [per-file JSON ledger](../out/phase0-supervised-source-review-20261019-1/inventory.json)
supersede historical counts, not historical runtime evidence. The original
stage marker is preserved; corrected nullable-adapter stage, archived supervision
sources and temporary-tree emulator patch replay are separately authenticated.
Counting now includes patch-created files that `git diff HEAD` omitted.

Reviewed successor changes and containment responsibilities:

- `WonadClientSupervisor.kt` is process-lifecycle glue, not a desktop session
  grant. It resolves only the fixed package/service for the foreground unlocked
  user, requiring exact signer/ordinary UID/package ownership through the
  controller, enabled/exported service and exact `STATUS_BAR_SERVICE` caller
  guard. Stopped, suspended and disabled clients remain ineligible. No consent,
  stopped flag, desktop layout or credential is written.
- Binding callbacks capture their exact `ServiceConnection`; retired callbacks
  cannot mutate a replacement. Pending binds time out after 15 seconds. Retry is
  bounded to 1/2/4/8/16/30 seconds; a 60-second healthy connection resets history.
  A stop re-resolves the captured user/UID/version/update-time tuple before
  affecting a service. These checks do not replace Binder/native admission or
  prove every package-update/lock race at runtime.
- `WonadController.kt` keeps reconciliation and supervision on the Shell
  executor. Eligibility combines controller/API readiness, matching Shell user,
  consent, clear keyguard and native eligible-display observation. Supervision
  runs after desktop reconciliation even when reconciliation fails; its own
  eligibility and authorization still gate binding. Lock handling revokes the
  desktop first and then reconciles lifecycle; no unconditional phone-input ban
  or permission grant is introduced.
- `NativeDesktopController.hasEligibleDisplaysForLifecycle()` reuses actual
  trusted/public/secure, on/interactive non-phone display enumeration and native
  display identity rows. It does not open a session. The ordinary broker still
  independently authenticates the client, active user, consent and native lease.
  The separately frozen [SUPERVISE contract](../os-integration/SUPERVISION.md)
  adds no window-management Binder methods or privileged APK permission.
- The corrected nullable framework-adapter function types preserve nullable
  callback/Bundle values instead of an incompatible Kotlin override. The
  authenticated 41-patch framework ledger retains original caller checks,
  bounded focus workers, epochs, cancellation and token validation. Source
  compatibility is not proof of their real Binder race schedules.
- Goldfish's front-buffer fix retains the acquired `BufferItem` while the host
  still displays it, releases the previous item after replacement, allows two
  acquired buffers, checks acquisition and serializes frame/pipe writes. This
  repairs emulator buffer ownership, not physical-phone rendering. The Java
  fix initializes the display manager/table before starting its listener,
  establishing the `Thread.start` publication edge when the host replays ADD.
  Both source postimages match the image's packaged provenance.

Remaining evidence limits: this is not independent review sign-off or full
source-to-binary reproducibility. Emulator tests cannot establish Pixel 10
driver, suspend, hub, StrongBox or update behavior. The development signer is not
production AVB/OTA or release-client custody. Real dispatch/replacement,
revocation/lock/user/failure, Recents and ordinary-phone qualification gates in
TODO.md remain open unless their exact-artifact runtime evidence passes. No
historical host/model test has been promoted to a new-image runtime pass.

This records bounded source-review checkpoints for the Wonad changes staged in
the historical `phase1-custom-4`, `phase1-custom-5` and `phase1-custom-6`
checkouts, and the current
`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`. It inventories the
privileged surface and records the intended failure and recovery owner for every
ordered patch. It is not a runtime qualification, a security certification, or
evidence that the ARM64 Pixel 10 image boots.

## Current source-versus-binary boundary — 2026-10-13

The earlier custom-7 build has now completed successfully. Its retained
[original receipt](../out/phase1-native-candidate-custom7-5-5/build-evidence/x86-custom-receipt.json)
has SHA-256 `9be626e4a21d8bfa30b18052174b6bad0310689e8f60b64dee3c20ed3d0b4b32`,
records compiler/container exit 0, no OOM kill, and a successful build log.
The actual SystemUI APK hash is
`c363b95791612669a16cb427d8cdedcfae43427b3e5e564fe122c838198910ea`.
This supersedes only the earlier “compiler still running” status, not any
runtime, ARM64 or production-signing qualification.

The current Mournblade modem-corrected image preserves those OS bytes. Its
corresponding-source archive has SHA-256
`b6432d0d4bfd1a8922c682657b652fa8b7d8b3d11c4524294a198d3dd85ea4db`.
Its compiled `NativeDesktopController.kt` source remains
`7a402bd3006a0e81df84df9e8ab737a49f7580fdb75adb92d8406659ea61eb6b`;
it does not contain the later duplicate session-close fix.

That source finding concerns positive Rust reconciliation: `Authority.reconcile`
clears the authority before returning a revocation reason. The previous Kotlin
adapter then attempted operation 7 against the already absent authority and
reported “Native session retirement declined.” Current source
`bce1dedb236552a14727ba1cf25a60541342f00e362aacc75e4bf842c52a0498`
skips only this redundant Rust close when reconciliation returned a positive
reason. Negative/error results still attempt the close. Exact Java owner and
picker invalidation, native UI/shortcut/focus cleanup and terminal callbacks
remain attempted; genuine cleanup failures remain visible.

The compiled teardown harness passes 121 assertions and the Rust authority
suite passes five tests. These are source-level prerequisites, not evidence
that the changed controller has run in SystemUI. Fresh custom-8 source
preparation has completed: pristine, copied-pristine and staged full source
audits passed with unchanged preparation tools. Its
[receipt](../out/phase1-custom8-source-preparation-20261013-1/receipt.json)
has SHA-256 `29d33e4dc4bd855daf18b042a0f6254209148bbcfde3029e05afbe311b6aaeba`;
the staged controller hash is the corrected `bce1dedb…` above. This is source
preparation only; no new compiler has started. A new actual OS build and exact-image runtime
qualification are still required. No historical build receipt or delivered
image is relabelled as containing this fix.

### Late retired-owner queue work — source correction, not runtime closure

The original `bce1dedb…` controller also authorized an old queued UID before
checking exact session ownership in `enqueue` and `drainQueueOverflow`. A
Binder thread can pass admission, pause before posting, and post after its
lease is retired and a replacement admitted. If the original UID has lost
admission, unscoped error cleanup could revoke that replacement.

Current shared source `0194a5f786b4de72ef877b240e45d53824d8512941e8f675df9c1eed8947e093`
marks retirement closed, fences exact session/captured UID before worker
authorization, and scopes both error cleanup and deferred stale-observation
recovery to that original session. Current-owner authorization/bridge failures
still fail closed; queue permits still release exactly once. There is no public
SDK or trust-policy change. Session-owned shortcut/picker callbacks and failure
guards and the outer completion poll carry the same exact-owner scope, including delayed stale-observation
recovery. Root compiled the actual enqueue bodies (23
assertions), actual owner/error/overflow bodies (17 assertions), and unchanged
dispatch cancellation source (348 assertions). The broader 25-test cleanup,
completion and Recents regression passes; a further 24-test owner/conformance
host subset passes after the final poll correction.
An additional compiled harness executes the original completion-poll, guarded
recovery and finish bodies with 13 assertions: queued retired polls, delayed
stale recovery, replacement during reconciliation, current-owner failures and
ordinary successful focus completion. JNI/WMS observations and native
completion decisions are explicit doubles, not fault-injected Android evidence.
The JVM doubles do not qualify PackageManager, Binder, WM or native runtime.

The custom-8 preparation receipt above still describes the earlier source.
It has not been overwritten or relabelled. Fresh custom-10 preparation now
passes all three full 1,057-project source audits, with unchanged preparation
tools and this exact controller. Its receipt is
`2e615059b27b95525a216374954ebd107d0ccde8b7f9daebf0eaa3afa01431e0`.
A full OS build and deterministic live retained-worker/replacement gate still
remain required. The current modem image contains compiled-7's `7a402bd3…`.

## Current custom-7 source checkpoint — 2026-10-11

The current schema-4 marker is 26,408 bytes with SHA-256
`5fb1f000c37ab702bbd2722d4dde6d1936d792533d2e76798e8ce59e271c0d5d`.
Root replayed the read-only check after the final packaging/tool regressions;
it returned `PASS: exact owned Wonad stage, patches, targets and tools verified`:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 android/platform/stage-os.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7 \
  --verify-only
```

There are still 57 owned files, 16 stage-tool references, 46 ordered patches
and 64 platform targets. The current owned stage totals 482,809 bytes, including
14 Rust files / 3,269 physical lines / 101,732 bytes and 26 Kotlin files /
6,176 physical lines / 344,785 bytes, with no owned Java source. Its ordered
staged-file ledger SHA-256 is
`23f065469a1783f7191c988f45329cea83ca5f6c2da2d82dc8c113dff8b5c805`.
The signer is still the development identity below. The public SDK and
packet-3 APK compile bindings are unchanged; no production identity or
runtime qualification follows from this inventory.

The historical custom-6 stage added command-disabled containment at the
initial and late-unhandled stock shortcut seams and the related exact-claim/
departure bookkeeping. Compared with custom-5, its three changed owned files
were `WonadUiBridge.kt`, `WonadInputBridge.kt` and
`NativeDesktopController.kt`; its only changed platform target was
`KeyGestureController.java`, SHA-256
`3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`.
The preparation record retains the actual 39-test source/compiled regression
and the modeled-framework limitations:
[custom6 preparation](../out/phase1-custom6-source-preparation-20261011-1.md).

Custom-7 changes exactly one owned source from custom-6:
`WonadNativeBridge.kt`, SHA-256
`3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`.
All ordered patch, platform-target and stage-tool maps are unchanged from
custom-6. The corrected path blocks newly populated app input when a sticky
native display has no valid lease. It weakly records only a Wonad-owned
false-to-true `DROP_INPUT` transition and restores only that bit before every
eligible population/recovery/phone-migration exit. Existing stock drop flags
are not claimed or cleared. The actual InputMonitor hook runs after stock
population under the WMS global lock, before publishing the changed handle.
The [independent input review](../../../wonad-phase1-build-evidence/phase1-native-app-input-independent-review-20261011-1.md)
has SHA-256
`b263c54e9dfe37fdf34cff92e20aa46e2e0322c0ec90b79bd6040cdc9eb36be6`
and retains the red-before control plus the final 17-test root replay. This
does not establish when InputDispatcher stops using an earlier-published
handle, revoke an already-routed event, or promise an atomic expiry-to-surface
commit deadline.

The current build is the separate `custom7-5` attempt, started at
`2026-10-11T13:24:44.738257435Z`. Its actual full preflight passed, but no
successful compiler exit, sealed custom receipt/comparison, candidate image
or fresh runtime result exists yet. The
[custom7 preparation record](../out/phase1-custom7-source-preparation-20261011-1.md)
identifies the exact source, output, driver and future receipt paths. The
later ordinary-UID and candidate-packaging corrections are outside this live
OS stage/tool input closure; they did not require a compiler restart.

## Historical custom-5 source checkpoint — 2026-10-11

The source at this checkpoint was `phase1-custom-5`, not the stopped `phase1-custom-4`
build. Its schema-4 stage marker is 26,408 bytes with SHA-256
`5015daa149185f2376ff719026b8e7cf86556d8dc81f1e3e225f54f077b12cd3`.
An independent read-only verification on 11 October returned
`PASS: exact owned Wonad stage, patches, targets and tools verified`:

```sh
python3 android/platform/stage-os.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-5 \
  --verify-only
```

The marker still binds 57 staged files, 16 tools, 40 framework patches, four
Launcher3 patches and two Goldfish patches, with 53/9/2 platform targets.
Read-only comparisons of each project's changed-path set against the marker
found no missing or extra paths. The signer remains the development identity
documented below, not a production certificate.

Comparing the two stage markers found exactly one changed owned source:
`os-integration/src/org/wonad/desktop/broker/NativeDesktopController.kt`, now
SHA-256 `a4234354c608dd78d9b499b4a1a7c2afc9b87b988344c91dc9c49be4f2766421`.
All staged tool, ordered patch and platform-target hash maps are unchanged.
The review finding was a Recents destination fallback: a removed or stale
focused destination could silently select another live monitor. The current
`recentsDestination` requires a unique match for both the selected opaque
display token and the live shell generation. It has no first-monitor fallback;
missing, removed, stale or duplicate matches return unavailable. Eligibility
and execution both use that helper, and execution rechecks phone focus and
client admission before the WMS transfer.

The two focused source/compiled tests in
`android/tests/test_native_recents_and_departure_failures_compiled.py` pass
against that checkpoint's helper. They exercise exact selection, removal, stale
generation, duplicate matches, independent lease cleanup and exact-session
failure ownership. This is narrow source/fixture evidence, not real Binder,
Launcher3, display-hotplug or emulator proof. The stopped custom-4 build and
its preserved abort record must not be presented as a successful candidate.
The custom-5 OS build, complete build receipts, binary comparison and every
runtime/release gate remained pending at this checkpoint. Its compiler was
later deliberately stopped; custom-6 was superseded before compiler launch.
Neither source nor attempt may substitute for current custom-7 evidence.

## Result and freeze decisions

The source at the initial review checkpoint appeared coherent under the static
checks and matched its authenticated staging marker, but a subsequent full
build found the Kotlin visibility defect recorded below.
The custom changes are much larger than a small compatibility shim: they alter
WMS/system-server focus, input, task, launch and display paths; WM Shell and
SystemUI policy; Launcher3 Recents and taskbar paths; and emulator product/input
configuration. That breadth is justified only if the exact-image failure and
phone-regression tests at the end of this document pass.

No privilege bypass was established by this source review. That statement must
not be read as proof that there is none. The two freeze findings are resolved in
the Wonad source and patch set:

1. The uncalled `setWonadExternalUiLease` Binder operation and its public Kotlin
   wrapper were removed. `setWonadNativeUiLease` is now the only SystemUI-to-WMS
   UI-claim entry point; it still reaches the shared private implementation used
   by the native takeover and recovery paths.
2. Ordinary apps can no longer start the consent activity. The real
   `WonadSettingsActivity` requires the signature-level `android.permission.DUMP`
   for an explicit shell diagnostics path which is additionally restricted at
   runtime to root/shell on debuggable builds. The separately signed Wonad client
   uses `WonadClientSettingsActivity`, an alias guarded by
   `org.wonad.desktop.permission.OPEN_OS_SETTINGS`. That permission is
   `signature|knownSigner`, and its sole known signer is generated from the same
   public DER certificate digest pinned by the broker. The activity then checks
   the launching UID/package against the broker's active-user, sole-package and
   signer rules (with only same-UID/system and debuggable root/shell diagnostic
   exceptions).
   The activity remains
   OS-owned, secure, overlay-hidden and touch-obscuration-filtered, rejects a
   locked/non-current user, and requires an explicit click before changing the
   secure setting.

The first full build of the restaged `phase1-custom-3` checkpoint exposed a real
source defect at the `WindowManager-Shell` Kotlin compile step: five controller
call sites attempted to access the nested `Session.callbacks` property even
though that anonymous-object property was private. This was not an
infrastructure failure and `custom-3` is not a candidate. The fix keeps the
anonymous dispatcher private (avoiding Kotlin's public anonymous-type erasure to
`Any`) and exposes only four narrow `Session` forwarding operations: in-flight
query, snapshot, result and revocation. A compiled regression fixture now calls
those same forwarding operations from an enclosing controller.

A subsequent static review also hardened the stock-wallpaper helper's user
handoff boundary. Its native-display scope now requires WMS's current user and
ActivityManager's current user to agree, both when scope is captured and when it
is revalidated. This prevents a WMS/AM user-transition interval from acquiring
wallpaper-retirement authority while retaining the separately authenticated
show-for-all-users behavior of the genuine SystemUI wallpaper activity.

These changes alter staged files and the authenticated patch/tool ledgers. The
`phase1-custom-4` checkout was recreated from the pinned manifest and restaged
after both fixes. It was subsequently superseded by the custom-5 checkpoint
above. Superseded checkpoints and the failed `custom-3` build evidence are
review history only and are not candidate inputs.

The staged signer is a development certificate with SHA-256
`3183261f28256159ad5e488d8a34854e77f36e14348720daae7f8cae7a8c26ff`.
It is not a selected production Wonad signer. The final signer choice therefore
remains a Phase 1 blocker even though the current pinning mechanism can be
reviewed and tested.

## Evidence and reproducibility boundary

The source pin is `android/grapheneos.lock.json` schema 2, GrapheneOS release
`2026100600`, production target `frankel-cur-user`, with these reviewed project
revisions:

| Project | Revision | Ordered patches | Exact changed targets |
| --- | --- | ---: | ---: |
| `frameworks/base` | `84183aff99be5e156dc0446a6fa2d4a7150f4bc3` | 40 | 53 |
| `packages/apps/Launcher3` | `47accce386f2abdc84e87c05b5587be6e0b0854f` | 4 | 9 |
| `device/generic/goldfish` | `1facfe03b3519c3413a51d2ea56400bbade0b4c3` | 2 | 2 |

The historical custom-4 `external/wonad/.wonad-stage.json` is schema 4. It records 57
owned files, 16 staging/release tools, the three revisions above, the signer
digest, all 46 ordered patch names and SHA-256 digests, and the complete
post-stage bytes of every patch target. The marker is 26,408 bytes with SHA-256
`8ac16db268b7be0ec2782da982922e68b705a5bd1e6c19b60b256912ef49b2ee`.
On 2026-10-11 this command returned
`PASS: exact owned Wonad stage, patches, targets and tools verified`:

```sh
python3 android/platform/stage-os.py \
  --source /u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-4 \
  --verify-only
```

The 57 files include the generated known-signer resource and the serialized
callback dispatcher, its private-callback forwarding fix and the guarded native
wallpaper helper. Verification of an older checkout is expected to fail; it
must not be substituted for the custom-7 marker-bound source used by the
current build. The custom-4 marker and command here describe only that earlier
source checkpoint; current verification is recorded above.

The forwarding fixture and wallpaper helper fixtures establish the two narrow
source regressions above. They do not establish that `custom-4` compiles as a
whole, boots, or behaves correctly at runtime. Full custom build, matched
baseline comparison and exact-image qualification remain pending.

An independent `git status --porcelain=v1 -z --untracked-files=all` comparison
found that each project's changed-path set exactly equals its marker target set:
53/53, 9/9 and 2/2, with no unexpected or missing path. This establishes the
owned staged delta at those three project revisions. It does not authenticate a
built image, prove that every other manifest project is clean, prove compiler
output, or replace the baseline/custom build comparison and release receipts.

## Trust, process and language boundaries

The current 57-file `external/wonad` stage comprises 14 Rust files, 26 Kotlin
files, 12 AIDL files, two XML files, one Soong file, one license and one DER
public certificate. There
is no owned Java source in that module. The patch targets are nevertheless
Java-heavy: the unique `frameworks/base` targets are 29 Java, 16 Kotlin, 2 AIDL,
4 Soong, 1 XML and 1 ProGuard file; Launcher3 adds 3 Java, 5 Kotlin and 1 XML
target. Rust preference therefore reduces policy implementation in JVM code but
does not remove the Java framework trust boundary.

- The separately installed `org.wonad.desktop` APK is an ordinary application
  UID. Its package must be the sole package for that UID, it must have no shared
  UID, one current signer, no signer lineage, and the active-user UID/package
  relation and signer digest are re-resolved. The APK receives opaque scalar
  task/display identities, not Android task IDs, `WindowContainerToken`s,
  `SurfaceControl`s or input channels.
- The exported broker runs inside privileged `com.android.systemui`. Binding is
  not authority: every broker/session call rechecks the calling UID/package and
  signer. SystemUI owns orchestration, catalogues, callbacks, renewals and
  conversion between the neutral APK contract and platform-native observations.
- `system_server` remains the final authority for real `DisplayContent`, `Task`,
  `ActivityRecord`, input and surface objects. Every new hidden WMS Binder entry
  enforces `android.permission.STATUS_BAR_SERVICE` and the exact system-user
  SystemUI UID before any identity clearing or native authority work.
  WM-object operations then use the global lock; the scalar identity-epoch
  query and input-claim path do not pretend to acquire that lock.
  The pinned SystemUI manifest uses `android.uid.systemui`: this is its trusted
  shared-UID group, not a package/PID distinction within that group. It is not
  blanket admission for every platform-signed APK. Emulator-only platform
  fault instrumentation deliberately runs inside that trusted process; it does
  not meet the separate ordinary Wonad policy-client UID and signer checks.
- `libwonad_broker_core` is a Rust `rlib`; Rust JNI libraries host its bounded
  decision state in SystemUI and system-server. Kotlin copies scalar arrays to
  and from JNI. This is a language/FFI boundary, not process isolation: JNI UB,
  an abort, or an uncaught fatal error can still terminate a privileged host.
- Java hooks are deliberately short entry points into Kotlin bridge objects,
  but they execute on high-risk WMS, input, launch, hierarchy and SystemUI
  lifecycle paths. The lock, caller-identity and reentrancy assumptions require
  compiled platform tests and live race testing.
- The public certificate is embedded; no private APK, AVB or OTA key is present
  in the staged tree. Production key custody and release signing are outside
  this source review.

### Recovery ownership

`system_server` owns the sticky physical-display claim and the final black/input
containment. Client death, SystemUI death, timeout, lock, consent loss or a
failed frame parks a claimed monitor instead of returning it to Android UI.
SystemUI owns renewal and establishment of a fresh authorized generation. An
actual display removal is the release boundary; reconnect creates a new native
attachment. Launcher3 owns cleanup only for its own taskbar/Recents UI objects.
An OS-glue defect cannot in general be repaired by updating the Wonad APK: its
recovery owner is an OS update, or an image rollback/recovery path.

This fail-black design trades availability for containment. Exact-image tests
must prove that it neither leaks stale content/input nor strands the phone, and
that unplug/reconnect and a fresh valid session are reliable recovery paths.

## New and modified cross-process interfaces

This inventory covers custom cross-process surface introduced by the staged
delta. Existing Android RPCs used internally (for example ordinary task
organizer operations) are dependencies, not new Wonad interfaces.

### APK to SystemUI: frozen desktop API v3

The exported component is
`com.android.systemui/org.wonad.desktop.broker.WonadBrokerService`, selected by
action `org.wonad.desktop.BIND`. `onBind` returns a Binder only for that action;
the absence of a manifest permission is intentional because the independently
signed client cannot hold a platform signature permission. Per-call identity
and signer checks are therefore the security boundary.

- `IDesktopBroker`: `getApiVersion`, `getCapabilities`, `openSession`.
- `IDesktopSession`: `applyFrame`, `focusTask`, `closeTask`,
  `enableShortcuts`, `heartbeat`, `release`, `enableExternalUi`, `showShell`,
  `launcherPage`, `showLauncher`, `selectLauncher`, `showTransferPicker`, and
  capability-gated `applySignedFrame`.
- `IDesktopCallback` (oneway): `onSnapshot`, `onCommand`, `onResult`,
  `onRevoked`.
- Parcelables: `DesktopDisplay`, `DesktopFrame`, `DesktopLaunchEntry`,
  `DesktopLaunchPage`, `DesktopPlacement`, `DesktopRect`,
  `DesktopShellRegion`, `DesktopSnapshot` and `DesktopTask`.

The APK also exposes exactly three fixed activities guarded by
`android.permission.STATUS_BAR_SERVICE`: `.ExternalHomeActivity`,
`.ExternalShellActivity` and `.LauncherActivity`. SystemUI supplies bounded
scalar extras/cataloque IDs and WMS independently authenticates the live
component, UID, permission, generation and physical attachment.

Remote callbacks leave Shell's serial executor through a bounded serial
dispatcher. Revocation marks the generation terminal without waiting, drops
queued late callbacks and orders the terminal callback after only an already
in-flight transaction. A five-second in-flight watchdog first parks the exact
desktop, revalidates the original user's sole-package/no-lineage signer, and
then uses SystemUI's added `android.permission.KILL_UID` solely to kill that
exact dedicated Wonad UID. This releases Binder backpressure and the bounded
worker; no replacement lease is admitted while any old callback worker exists.

### SystemUI to system-server: hidden `IWindowManager` surface

The custom hidden calls are:

1. `setWonadShortcutLease`
2. `getWonadNativeDisplayState`
3. `getWonadNativeTaskState`
4. `setWonadNativeUiLease`
5. `applyWonadNativeFrame`
6. `applyWonadNativeSignedFrame`
7. `isWonadNativeFrameApplied`
8. `operateWonadNativeTask`
9. `transferWonadNativeTask`
10. `isWonadNativeUiDisplay`
11. `getWonadNativeIdentityEpoch`
12. `isWonadNativeInteractionBlocked`
13. `setWonadFocusLease`
14. `getWonadFocusedDisplayId`

The frame calls carry arrays containing copied current/desired scalar state plus
SystemUI-held exact task Binder tokens and expected UIDs. Those native tokens do
not cross the APK boundary. WMS resolves and revalidates every native object
under its lock. `IShortcutService.notifyShortcutKeyPressed` is the return
callback for a fixed command number; it is not a raw key-event channel.

### Launcher3 to WM Shell: trusted Recents transfer

`IDesktopMode` adds `canSendTaskToWonad` and `sendTaskToWonad`. Launcher supplies
observations for one Recents card: task ID, user, last-active time, base
component and exact task Binder token. The WM Shell implementation runs the
existing task-permission check, independently verifies the active-user
`com.android.launcher3` UID, re-resolves the live task, and lets the OS adapter
choose the destination. Launcher cannot name a monitor or submit a window
transaction through this API.

### Consent and control-plane state

`wonad_external_desktop_enabled` is a per-user secure setting written by the
SystemUI-owned consent activity and observed by the broker. It is necessary but
not sufficient for authority: active user, unlock/interactive state, exact APK
identity and at least one trusted, secure, public external/virtual display are
also required. Loss of those conditions must revoke or park the generation.
The ordinary Wonad app can reach that UI only through the signer-pinned activity
alias and the activity's exact package/UID recheck. Debug-build shell diagnostics
use the separately permissioned real component; an
unprivileged package is rejected by PackageManager before the activity is
launched and therefore cannot manufacture or foreground a consent prompt.

## Stock-UI and stock-policy suppression map

| Subsystem | Hook points | Required scope/failure behavior |
| --- | --- | --- |
| System decorations | WMS `shouldShowSystemDecors`; final WMS root-type admission; SystemUI decoration repository, status-bar orchestration/window store, navigation bar and privacy-dot lifecycle | Suppress and retire status, shade, navigation and privacy-dot windows only on a sticky native external attachment. Phone display 0 remains stock. Unknown ownership fails closed for external creation. |
| Taskbar | Launcher3 taskbar manager, display dependency readiness and final `addView` admission | Destroy or decline the external taskbar across queued callbacks and ownership races; retain ordinary phone behavior. |
| Back gesture | per-display `EdgeBackGestureHandler` creation, enumeration and final factory/dispose boundary | No stock external input spy on claimed or parked attachments; phone gestures remain stock. |
| Desktop/window decoration | desktop/caption view models and `DesktopTasksController` | Do not create captions, apply stock desk/window policy or process stock task changes on native attachments. |
| Desk/repository fallback | task repository, freeform fallback, desk-root organizer and display-event handler | Evict cached stock desk state, decline new roots, complete waiters, and retire only exact empty SystemUI-created roots. |
| Desktop wallpaper | Shell precheck plus WMS launch, window, restore, reparent and transaction boundaries | Retire/reject only the PM-authenticated SystemUI `DesktopWallpaperActivity` while WMS and ActivityManager agree on the current user; ordinary app and phone wallpaper behavior remains stock. |
| Native background/shell | secondary-home resolution, home visibility, shell input sink, layer/input completion and IME parent readiness | Keep the authenticated APK Home as background, preserve transparent shell holes, layer/input completion, and recompute stale IME parents without granting the APK native handles. |
| Protected phone UI | permission/location routing, interaction-block query and display-raise guard | Route exact trusted prompts to display 0, block external interaction/display raising while protected UI is active, and preserve Activity results. |

## Ordered patch review

The order below is the order enforced by `android/tools/stage_contract.py` and
recorded in the schema-4 marker. “Risk” describes the principal regression or
race to test, not a finding that the failure has occurred.

### `frameworks/base`: broker, focus and lifecycle (1–15)

| # and patch | Effect | Principal risk | Recovery owner |
| --- | --- | --- | --- |
| 1. `wonad-broker.patch` | Wires the SDK/Kotlin/Rust JNI into WM Shell, SystemUI and system-server; exports the per-call-authenticated broker and separately permissioned consent entry points; adds shortcut lease/input interception and exact-UID recovery for a permanently backpressured callback. | A build/link/JNI failure can disable or crash a privileged host; a permission-resource mismatch can make consent unavailable; an input-hook error can steal or leak keys; misuse of `KILL_UID` could terminate an unrelated app. | SystemUI broker fails closed; package installation enforces the generated known-signer pin; callback recovery first parks the display and revalidates original user, sole package, non-shared UID, no signer lineage and exact stored signer before killing that UID; system-server lease/bridge consumes only owned keys; OS update for code defects. |
| 2. `wonad-focus.patch` | Adds focus lease; integrates leased top-resumed selection, raise observation and visibility exclusion. | Focus/lifecycle divergence, wrong top-resumed app, or hidden task receiving input. | `WonadFocusBridge` validates exact live tasks and clears leases on death/expiry; system-server owns repair. |
| 3. `wonad-focus-lock.patch` | Adds a tiny Java wrapper that executes supplied bridge work under WMS global lock. | Lock-order, reentrancy or long critical-section regression. | WMS/system-server; callers must remain bounded and nonblocking. |
| 4. `wonad-focus-order.patch` | Preserves ancestor raise direction and retained resumed focus when always-on-top ordering adjusts a child. | Incorrect z-order or focus on cross-task raises. | WMS bridge revalidation; lease cleanup or display removal restores ordinary ownership. |
| 5. `wonad-focus-lifecycle.patch` | Feeds actual input-focus changes to the Wonad focus bridge. | Recursive focus churn or stale focus bookkeeping. | WMS bridge; failure must not outlive the exact lease. |
| 6. `wonad-organizer-death.patch` | Preserves exact leased app tasks before a dead Wonad/SystemUI organizer tears down its roots. | Preserving a foreign/protected task or losing an app on SystemUI death. | system-server checks organizer UID/native objects and reparents survivors on the same display. |
| 7. `wonad-display-settings-lifetime.patch` | Prevents delayed virtual/overlay display teardown from deleting settings for a replacement with the same stable ID; adds WmTests. | Stale settings retained for a truly removed display, or replacement settings erased. | WMS settings provider; final valid replacement removal performs cleanup. |
| 8. `wonad-focused-display.patch` | Adds a SystemUI-only authoritative focused-display query, including an empty desktop. | Information exposure or stale numeric display identity. | Exact SystemUI permission/UID gate and live WMS root observation. |
| 9. `wonad-focused-display-tests.patch` | Adds real bridge tests for permission, UID/user and focus observation. | Test-only patch can fall out of build/test discovery and gives no runtime-race assurance. | Platform test owner; run the named WmTest on the exact tree/image. |
| 10. `wonad-recents-framework.patch` | Adds the two trusted Recents transfer RPCs and delegates exact-task validation/destination choice to the broker. | Recycled task ID/token, forged caller, stale destination or blocking Shell call. | WM Shell permission + Launcher UID checks; broker revalidates live task/session. |
| 11. `wonad-recents-taskkey.patch` | Carries the live `WindowContainerToken` through the Recents `TaskKey` parcel. | Parcel-order compatibility regression or stale token reuse. | Launcher/WM Shell exact observation checks; failure returns unavailable. |
| 12. `wonad-external-ui.patch` | Adds UI claim, suppresses system decors, selects fixed secondary Home, hooks final removal and introduces Wonad force-hidden state. | Stock UI leak, overbroad suppression or a claim/removal race. | The single `setWonadNativeUiLease` entry reaches WMS's shared private claim implementation; sticky WMS ownership and display removal provide the recovery boundary. |
| 13. `wonad-external-ui-lifecycle.patch` | Calls claim removal at the start of `DisplayContent.remove`, not only immediate destruction. | Double cleanup or a teardown/replacement race. | Idempotent `WonadUiBridge.onRemoved`; WMS attachment identity. |
| 14. `wonad-external-wallpaper.patch` | Stops Shell desktop wallpaper precreation when the external display has no system decorations. | Hiding wallpaper on an ordinary transiently-unqueryable display. | Shell uses WMS decoration result; later WMS wallpaper boundary is authoritative. |
| 15. `wonad-external-ui-visibility.patch` | Applies Wonad force hiding without stock `Task.moveToBack` reparenting. | Hidden tasks remain wrongly ordered/focusable after park/reveal. | WMS bridge records/restores exact native state; physical removal/recovery path. |

### `frameworks/base`: native frames and stock desktop exclusion (16–30)

| # and patch | Effect | Principal risk | Recovery owner |
| --- | --- | --- | --- |
| 16. `wonad-native-frame.patch` | Adds native display/task/frame/task-operation APIs, policy hidden state, explicit shell layers/input regions and completion observations. | Largest mutation surface: partial frames, wrong task/surface/input region, stale token/UID or compositor/input mismatch. | WMS revalidates exact objects under lock and parks the whole generation on commit failure. |
| 17. `wonad-native-shell-policy.patch` | Disables stock window captions and desktop transitions/policy on native attachments. | Stock policy racing takeover or being suppressed on an unowned screen. | SystemUI queries sticky WMS ownership; unknown external ownership fails closed. |
| 18. `wonad-native-task-repository.patch` | Refuses new stock repository admission and evicts pre-takeover desk/perceptibility state. | Cached stock transactions still mutate native tasks, or perceptibility/OOM state regresses. | WM Shell removes only its own marks; WMS retains normal task lifecycle. |
| 19. `wonad-native-recovery.patch` | Exposes a system-server-owned opaque task identity epoch across APK/SystemUI restart. | Identity replay across `system_server` or UID reuse. | Epoch changes with system-server and identities bind exact Task+UID; SystemUI-only query. |
| 20. `wonad-native-input-completion.patch` | Requires visible/unpaused/unobscured input-handle state before reporting shell/observer completion. | False completion could expose holes or leave input dropped. | WMS completion check; lease remains black/input-consuming until complete. |
| 21. `wonad-native-task-bounds.patch` | Removes Android synthetic caption minima/fitting for exact native app leaves while retaining application minima. | Off-screen/unusable geometry or accidental effect on phone/system tasks. | Exact native-mode/app predicate; APK policy plus WMS bounds validation. |
| 22. `wonad-native-protected-ui.patch` | Adds SystemUI-only protected-window/interaction-block observation covering keyguard, protected phone UI and genuine routed permission flows as well as broker-owned selection/confirmation. | Missing a permission/keyguard/system dialog or overblocking normal app focus. | WMS examines live windows/users; broker folds in its own picker state and pauses mutations while blocked. |
| 23. `wonad-native-permission-routing.patch` | Routes an exact PermissionController request from a managed external app to a separate fullscreen phone task while preserving its result chain. | Permission spoofing, lost `ActivityResult`, wrong-display prompt or phone task reuse. | ActivityStarter authenticates source/result/controller/UID under WM lock and strips client placement. |
| 24. `wonad-native-shell-input-sink.patch` | Allows touch through holes only for the exact authenticated transparent shell Activity. | Tapjacking/input escape if the exemption matches another Activity. | WMS native object/component/UID/permission/generation/attachment checks. |
| 25. `wonad-native-location-button-routing.patch` | Extends protected phone routing to exact location-button `PendingIntent` provenance. | Forged/stale PendingIntent or wrong caller attribution. | AM-private provenance + WMS exact managed-source checks; otherwise stock path. |
| 26. `wonad-native-freeform-fallback.patch` | Prevents stock freeform fallback handler/observer from creating desks or submitting stale WCTs on native displays. | Coroutine suspension lets a pre-takeover transaction land afterward. | Rechecks ownership before each mutation and before final transaction submission. |
| 27. `wonad-native-shell-home-visibility.patch` | Treats authenticated native Home as non-occluding background after stock safety checks. | An opaque/foreign Home could stop occluding and expose content. | Exact Home component/UID/permission/attachment checks in WMS. |
| 28. `wonad-native-empty-stock-roots.patch` | Blocks/winds down stock desk roots, completes pending callbacks, token-binds root requests and retires exact empty prewarmed roots. | Root leak, callback hang/double completion, removal of occupied/foreign roots. | WM Shell completes all waiters; system-server retirement accepts only empty SystemUI-created exact roots. |
| 29. `wonad-native-signed-frame.patch` | Adds the capability-gated signed/off-screen frame operation. | Capability confusion or off-screen placement through ordinary `applyFrame`. | Separate method/Rust validator; WMS keeps shell/input containment and exact-object checks. |
| 30. `wonad-native-shortcut-priority.patch` | Gives only the fixed Rust desktop command alphabet priority over stock Meta gestures. | Stock/system shortcut regression, stuck modifiers or cross-display capture. | Input bridge still requires trusted event, focused eligible display and live expiring lease. |

### `frameworks/base`: complete takeover and protected paths (31–40)

| # and patch | Effect | Principal risk | Recovery owner |
| --- | --- | --- | --- |
| 31. `wonad-native-stock-gesture-ownership.patch` | Declines/removes per-display stock back-gesture handlers on native attachments. | External input spy survives restart/takeover or phone back breaks. | SystemUI per-display cleanup; display 0 always keeps stock policy. |
| 32. `wonad-native-stock-decoration-ownership.patch` | Filters decoration repository events and refuses status-bar construction on owned displays. | Queued repository state recreates chrome, or a normal external display loses it. | SystemUI checks affirmative WMS ownership at event consumption/construction. |
| 33. `wonad-native-stock-decoration-boundary.patch` | Adds final WMS window-type rejection plus race-safe status/nav/privacy-dot repository and lifecycle teardown. | Broad system-window rejection, leaked callbacks/views/input, or takeover race after a successful add. | WMS is final admission authority; SystemUI stops/removes exact local windows idempotently. |
| 34. `wonad-native-home-resolution.patch` | Propagates the caller's instrumentation allowance through secondary-Home resolution. | Test instrumentation could select an unintended Home/display. | Existing `canStartHomeOnDisplayArea` plus native exact-component checks; user build qualification required. |
| 35. `wonad-native-home-launch-params.patch` | Allows only the exact instrumented native Home to retain its external task display area instead of falling back to phone. | Overbroad instrumentation exception or phone Home relocation. | `WonadUiBridge.allowInstrumentedNativeHome` binds activity info and exact owned area. |
| 36. `wonad-native-stock-wallpaper-boundary.patch` | Rejects new stock `DesktopWallpaperActivity` launches/windows and retires exact existing solitary wallpaper tasks. | Mistaking ordinary wallpaper/app content for Shell wallpaper, cached token recreation, or acquiring authority during a user handoff. | PM-authenticated component/UID/system+privileged flags, matching WMS/ActivityManager current-user observations, and live attachment checks in WMS. |
| 37. `wonad-native-incoming-wallpaper-routes.patch` | Covers direct reparent, hierarchy WCT, task-fragment operations and recent-task restore with a conservative no-mutation route preflight. | Missed compound route leaks stock wallpaper; false positive rejects an unrelated complex WCT. | WMS rejects before mutation; stock operation receives failure and retains source hierarchy. |
| 38. `wonad-native-ime-parent-readiness.patch` | Forces IME-parent recomputation when the old launcher surface vanished even if the control target did not change. | IME flicker/mis-parenting or unnecessary recomputation. | WMS exact stale-parent predicate; normal IME controller performs the reparent. |
| 39. `wonad-native-protected-display-raise.patch` | Prevents a targeted key from raising a claimed external display over protected phone UI. | Phone prompt loses protection, or ordinary external focus is blocked. | WMS checks exact live native lease and protected-input state only. |
| 40. `wonad-native-stock-gesture-takeover.patch` | Wraps stock gesture-handler construction with post-create ownership recheck and disposal. | Ownership changes between precheck and map publication, leaking an input receiver. | SystemUI disposes the unpublished handler; WMS final window admission remains authoritative. |

### Launcher3 (1–4)

| # and patch | Effect | Principal risk | Recovery owner |
| --- | --- | --- | --- |
| 1. `wonad-recents-launcher.patch` | Adds “Send to Wonad,” eligibility query, screenshot/Recents exit, exact-task transfer and failure toast. | Blocking Overview, stale card transfer, loss of Screenshot/Split screen behavior. | Launcher fails unavailable; WM Shell/broker revalidate and choose destination. |
| 2. `wonad-external-taskbar.patch` | Uses WMS decoration ownership unconditionally for external taskbar create/recreate and tears down on denial. | Taskbar flashes/reappears from queued configuration callbacks. | Launcher3 destroys its root/resource; WMS owns final system-window admission. |
| 3. `wonad-external-taskbar-readiness.patch` | Waits for the correct per-display evaluator, retries boundedly and rechecks ownership before/after construction. | Infinite retry, use of phone dependency, or destroyed resource resurrection. | Per-display resource cancels retry on cleanup; manager destroys rejected taskbar. |
| 4. `wonad-native-taskbar-admission.patch` | Adds final admission around `WindowManager.addView`, including post-add rejection and reentrant-safe teardown. | View/input leak or double destruction during takeover/remove races. | `SafeViewManager` cancels pending adds and owns exact local view removal. |

### Goldfish emulator support (1–2)

| # and patch | Effect | Principal risk | Recovery owner |
| --- | --- | --- | --- |
| 1. `emulator-freeform.patch` | Adds the freeform-window-management feature XML to the x86-64 emulator product. | Emulator behavior diverges from Pixel 10 product configuration. | Development/emulator build only; never treat it as ARM64 device evidence. |
| 2. `emulator-meta-keys.patch` | Maps Linux key codes 125/126 to left/right Meta for emulator keyboard testing. | Host/emulator key mapping differs from physical hardware. | Emulator config; physical input qualification remains Phase 2. |

## Source-review conclusions

The intended authority split is sound in outline: APK policy is expressed as a
bounded neutral frame, SystemUI authenticates and translates, Rust validates
bounded scalar state, and system-server resolves exact native objects and owns
containment. The source consistently treats numeric display/task IDs as
observations rather than authority. Sticky ownership, independent leases,
caller UID checks, signer pinning, death recipients, generation/incarnation
checks and final WMS admission hooks are visible in the staged code.

The highest-risk areas are not the AIDL DTOs; they are the asynchronous seams:
SystemUI restart, owner death during organizer teardown, display-ID reuse,
queued decoration/taskbar/gesture callbacks, compositor-versus-input completion,
permission/result routing, and compound WCT/recent-task wallpaper ingress. Most
of the later patches exist to close one of those races. That is also why source
inspection and host fixture tests cannot establish release readiness.

The current hidden OS interface should be treated as part of the Phase 1 freeze
even though it is not published to APK developers. Any change to an
`IWindowManager`/`IDesktopMode` method, platform hook, caller check, signer pin,
or fail-black ownership rule invalidates this review and requires restaging,
baseline comparison and exact-image reruns.

## Remaining exact-image qualification

Before this source review can support the Phase 1 exit gate, the source-matched
x86-64 sibling must be built from the exact marker, compared with an unmodified
2026100600 baseline, packaged with authenticated receipts, and booted fresh.
At minimum, run and retain evidence for:

1. API and identity rejection: absent/uninstalled APK, wrong signer, platform
   signer, shared UID, multiple signers/lineage, inactive user, unsupported API
   versions, malformed/boundary arrays and stale/dead/recycled Binder task and
   display identities. Run both the product and separately signed conformance
   clients; from a real foreign application UID, verify both consent components
   are rejected before UI appears, while the exact client alias and debuggable
   shell diagnostic path still work. Verify no SystemUI/system-server/Launcher
   crash or ANR.
2. Real Binder concurrency: completion before cancellation, cancellation after
   dispatch, abandoned session-open, failed initial catalogue/page, replacement
   session and picker isolation, binder death during every outstanding request,
   callback receive-queue backpressure through exact-UID kill and healthy
   replacement recovery (including four sequential hung owners), and
   heartbeat/transaction/launcher timeout boundaries.
3. Real JNI/commit/fault ordering: Rust validation failure, JNI exception or
   unavailable library, callback death/throw, surface commit without input
   completion, input completion without observable frame, refresh failure,
   topology change during apply, and cleanup failure aggregation. No partial
   frame may be reported applied.
4. Fail-black lifecycle: lock/sleep, consent loss, APK crash/hang/update/removal,
   SystemUI kill/restart, system-server restart/guest reboot, owner death,
   display power loss and physical/virtual disconnect. Confirm black plus input
   consumption until a fresh valid plane is ready, then reliable recovery.
5. Three simultaneous monitors of mixed geometry/density/rotation, including
   empty and populated desktops, rapid display-ID reuse, at least 20 populated
   disconnect/redock cycles per clean boot over three boots, final-unplug phone
   recovery, bounded roots and no stale settings or native identities.
6. Complete takeover: no Android status bar, shade, navigation bar, taskbar,
   privacy dot, back-gesture spy, desktop caption/desk policy or Shell desktop
   wallpaper on any claimed/parked external monitor, including takeover races
   while each object is being created. Confirm ordinary unowned displays retain
   stock UI.
7. Phone regression: normal Home, Recents, Screenshot, Split screen, gestures,
   permissions, location prompts, lock screen, emergency/protected UI, IME,
   browser/input and user switching. Verify protected phone UI prevents external
   focus/display raise without stranding input afterward.
8. Task/layout behavior: tiled/floating reorder, focus versus always-on-top,
   hide/reveal, close, transfer, fixed/non-resizable/minimum-size apps, dialogs,
   hardware and software IME, launcher shell regions and signed/off-screen
   placement. Compare visible pixels and actual input regions after settlement,
   not merely callback success.
9. Recents transfer: exact live task to each destination; cancel; stale card,
   token/task-ID reuse, removed app/task/display, locked/disabled/unavailable
   client, multiple displays, picker replacement and preservation of existing
   Screenshot/Split screen actions.
10. Platform tests on the exact build, including
    `WmTests:WonadFocusedDisplayTests`, the added display-settings tests, relevant
    WMS/ATMS/input/SystemUI/Launcher tests, and matched baseline-versus-custom
    failure comparison. The fail-closed plan, runner, and comparator are now
    specified in [`PHASE1-UPSTREAM-TESTS.md`](PHASE1-UPSTREAM-TESTS.md); the
    source-matched paired result remains pending a successful `custom-7` x86
    build; the failed `custom-3` Kotlin compile is not such a result.
    Run SELinux enforcing and inspect denials.
11. One uninterrupted 24-hour platform/conformance soak with hotplug,
    lock/unlock, user changes, APK/SystemUI death, updates and malformed calls,
    tracking process start epochs, crashes/ANRs, FD/RSS growth and residual
    roots/tasks/input resources.

The ARM64 `frankel` user build, protected AVB/OTA/factory signing and offline
artifact verification remain separate Phase 1 packaging requirements. The
protected-key roles and build/sign boundary are specified in
[`PHASE1-SIGNING-CEREMONY.md`](PHASE1-SIGNING-CEREMONY.md), but no production
ceremony has yet supplied the required identities. The
bounded install, update, recovery and return-to-stock procedure is recorded in
[`PHASE1-INSTALL-UPDATE-RECOVERY.md`](PHASE1-INSTALL-UPDATE-RECOVERY.md) and
must be bound to the final operations/release evidence. Boot and ordinary-phone
qualification on a physical Pixel 10 remain Phase 2 and cannot be inferred
from a successful x86-64 emulator sibling.
