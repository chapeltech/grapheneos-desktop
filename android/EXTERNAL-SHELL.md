# External-screen takeover

The requested end state is a normal GrapheneOS phone on display zero and a
Wonad desktop on every attached external monitor. The external desktop must
use Wonad's Linux/XMonad profile: its layouts, borders, launcher, panels,
workspaces, keyboard actions and mouse operations. Android continues to render
app content, enforce permissions and deliver input, but does not choose the
external desktop's appearance or workspace policy.

> **Current-status note (2026-10-12):** the final section, “Authoritative
> Phase 1 OS-glue/interface checkpoint,” is the current interface and build
> status. Earlier references to API v2/API2, public `Native*` names, the
> 21-file draft SDK baseline, APK10, and numbered diagnostic products are
> retained as historical evidence only. They are not supported interfaces or
> qualification of the Phase 1 candidate.
>
> Implementation work is in [TODO](../TODO.md); the roadmap contains goals only.
> SDK 3.0.1 has two reproducible publication builds, but the final OS/fixture/
> runtime binding is unfinished. Keyboard review rejected the pending designs
> which still invoked stock Android Recents/launcher/long-Escape actions on
> healthy Wonad-owned displays. Their replacement remains external under
> review; no new qualified image is claimed. The deployment target is Pixel 10
> (`frankel`). The successful Frankel vendor G10 attempt is historical input
> evidence, not a current ARM OS build or signed candidate. Current build and
> physical installation guidance is in [PIXEL10-INSTALL.md](PIXEL10-INSTALL.md).

## Ownership and recovery

The separately signed APK owns policy and shell UI. The OS authenticates its
session, resolves actual task/display objects and applies bounded placement,
visibility and focus operations. Task tokens, transactions, compositor surfaces
and input channels stay in the OS. The language preference remains Rust for
bounded decisions, Kotlin for Android object adapters, and minimal Java hooks.

External UI ownership is a separate state from Android's display-content mode
and desktop eligibility. Claiming a monitor must not turn off app hosting,
change its persistent settings, remove it from topology, or mirror the phone.
Ownership identifies the exact native display incarnation, not an Android ID
that may be recycled. The phone cannot be claimed.

The connected-screen states are Android, live Wonad, and claimed/blank. A live
Wonad screen becomes blank on client death, heartbeat expiry, loss of consent,
lock or user switch. It must hide app content and consume external input. It
must not reveal Android's desktop, bars, taskbar or window captions. A fresh
authenticated, enabled, unlocked session may resume the claim. Physical display
removal ends the claim and returns surviving tasks to the existing undock policy.
Late callbacks from a removed display or old generation cannot affect a new one.

## Shell and policy

Wonad's secondary-home Activity supplies the external background. It does not
declare the primary HOME category or require overlay permission. The OS selects
it only for claimed external screens. The screen stays blank until its window
has drawn. The normal phone launcher and Recents remain available.

That ownership also forbids Android dispatch-stage Recents, app drawer,
window-management, screenshot and other stock desktop shortcuts on healthy
claimed screens. Fixed Wonad commands route to the APK; reserved Android UI
keys are consumed with balanced pair draining, while ordinary app keys and
modifiers remain app input. Ordinary external Escape must not start Android's
long-Escape Toast/QUIT/task-close policy. Every before/after-capture,
unhandled-key and fallback entry needs the same containment; capture flags
cannot bypass it. Phone/unclaimed behavior remains stock. The pending
implementation is not yet runtime-qualified. Existing global hardware
queueing/multi-key safety and SecurePaste are separate retained exceptions;
cross-origin hardware-chord mixing remains an explicit open review/test item.
The pre-target Assist/Voice Assist/PiP/global-key paths are a separate open
containment gap, not accepted hardware-safety exceptions. Ordinary
USB/Bluetooth keyboards may lack a reader-side display association, although
native hardware queueing resolves an intended display before its callback.
The required routing boundary is focus-based: the same keyboard may operate
either the phone or an external Wonad window. Deliberately focusing the phone
allows subsequent input there. A specific event already admitted for an
external target must not be redirected accidentally during asynchronous
processing, and focus/hotplug changes must not strand key state. There is no
permanent keyboard-to-monitor assignment or blanket phone-input prohibition.
Numeric IDs, guessed focus and asynchronous global reassociation cannot replace
the exact event/target checks. The dispatch-stage candidate alone is not full
takeover. The broad reader/filter-incarnation, board safety-realm and atomic
census projects are deferred unless a concrete focus-contract regression
requires a minimal change; known unsafe prototype mechanisms are not accepted.

The v3 APK now implements launcher/panels, borders and floating move/resize
input with the shared Elric policy. Runtime qualification of these replacements
is unfinished. Android captions may be removed only as part of installing those
Wonad operations. Trusted permission and transfer confirmations belong on the
phone. The app-selection UI belongs to Wonad on the invoking monitor.

**Historical API-v2 record (superseded):** the client-launcher candidate
implemented that app-selection split with additive v2 calls guarded by
`CAP_APK_LAUNCHER`. `launcherPage` returns at most 128 entries
from an OS-issued catalogue of at most 4,096 choices; subsequent pages must match
the live generation, display, workspace and catalogue. `showLauncher` starts
only Wonad's fixed ordinary Activity on that exact external display, and
`selectLauncher` consumes an entry index once. No Intent, app UID, task token,
surface or input channel is supplied by the APK. The existing Rust picker
validates one-shot scope/expiry; Kotlin re-resolves the selected application.
Potential reuse of a phone app requires a trusted phone-side confirmation.
Detached transient launcher tasks are removed before Android reparents survivors.
The APK rejects incomplete, reordered, oversized, expired or cross-scope pages;
its Activity also checks the process-local catalogue and actual display.
This is not the final neutral v3 shell contract or Linux-profile pixel parity.

**Historical API-v2 record (superseded):** the v2 policy had nine workspaces
and Android desk bookkeeping. The
final shell contract must instead expose bounded task placement, visibility and
focus observations; the APK owns workspace identities, counts, assignments and
reserved panel areas. The shared Wonad profile supplies layout and mouse/key
behavior. A successful v2 layout is not proof of this final contract.

FixedTextColumns arithmetic now lives in the backend-neutral
`Wonad.Policy.Geometry` library, and the Linux adapter calls it directly.
Regression oracles cover 68,040 FixedTextColumns configurations, including the
Elric 80-column/1024-pixel profile. The older Android v2 policy uses its existing
Tall/Vertical/Full modes. The new v3 APK calls the shared Elric native policy
engine, including FixedTextColumns and Full; its live pixel and input parity
are still unproved.

Phone Recents offers "Send to Wonad" only for a healthy authorized session.
It transfers the exact live task to the last-focused eligible monitor, rechecks
its native token at execution, and preserves the phone's foreground/focus.

## Historical runtime evidence and unfinished work (through 2026-10-09)

This section preserves the sequence of diagnostic candidates and failures that
led to the Phase 1 contract. It must not be read as current API documentation
or as cumulative qualification of a newer artifact.

- Clean Recents transfers passed on one monitor and on the last-focused second
  monitor: `out/recents-action-clean-{1,2}/report.json`.
- The clean three-monitor guest-input/workspace/floating/hotplug matrix passed:
  `out/recents-matrix-clean-1/report.json`. This is the pre-takeover OS/APK pair.
- The ownership state machine and private JNI adapter pass Rust tests/clippy.
  The first takeover OS and APK compile; APK unit tests and lint pass.
- The first takeover runtime exposed an InputEventReceiver channel-ownership
  error and an APK inset-controller startup error; both are fixed. The next
  clean runtime passed admission, full-screen bounds and removal of external
  bars, but cold app launch failed before Activity creation. The next candidate
  suppresses Android's desktop wallpaper on claimed displays and latches home
  draw readiness per authenticated generation, so normal background surface
  destruction does not blank healthy apps. That candidate passed cold launches
  and repeated exact-black pixel/input isolation checks after client death, but
  failed reconnect visibility and exposed a Launcher3 external-taskbar callback
  race. The next candidate recreates a missing external home on fresh sessions,
  updates native Activity visibility/resume when removing its hiding bit, and
  rechecks decoration ownership before Launcher3 recreates taskbars. Runtime
  acceptance remains pending. The combined candidate in
  `out/external-ui-ownership-7a/report.json` passes cold launch/rendering on both
  monitors, repeated exact-black screenshots, parked input exclusion, and phone
  home preservation, without the Launcher3 crash. Its reconnect still fails:
  stock `Task.setForceHidden` reparents organizer children behind Home, and a
  fresh v2 session assigns both monitors' tasks to workspace one. Candidate 8
  gives the Wonad-only hiding bit no hierarchy side effects and initializes
  per-monitor workspace assignments before capturing surviving tasks. Its
  `out/external-ui-ownership-8a/report.json` proves reconnect with preserved
  task/Activity identities, monitor placement, visibility and nonblack rendered
  pixels. A changed-resolution replug also completed, but the final crash gate
  rejected that run: Launcher3 lost its per-display feature evaluator between
  the native decoration check and taskbar construction. The next owned patch
  snapshots the exact display evaluator before construction, defers creation
  while it is unavailable, cancels deferred work on resource teardown and
  rechecks native ownership before adding a taskbar window. The diagnostic now
  exercises three changing-resolution hotplug cycles. Acceptance on that
  candidate and focused-secondary-monitor reopen coverage remain pending.
- `out/external-ui-ownership-9a/report.json` passes the expanded ownership
  diagnostic on a fresh enforcing emulator: both monitors launch/render,
  client death gives exact-black pixels and excludes mouse/key input, restart
  preserves task/Activity identities and placement, and all three resolution-
  changing replugs pass. No protected-process crash occurred in that run. This
  product predates the evaluator-readiness fix, so it is recovery evidence,
  not proof that the intermittent Launcher3 race is repaired. Its full-shell
  acceptance is explicitly not passed.
- Candidate 10, including the taskbar dependency-readiness patch, builds
  successfully. All three fresh runs in
  `out/external-ui-ownership-10{a,b,c}/report.json` pass the same expanded
  foundation diagnostic without a protected-process crash. Their exact
  product/APK hashes match, and all owned emulators stopped normally.
  `out/external-ui-matrix-10a/report.json`
  passes the current candidate's three-monitor behavioral matrix: keyboard
  launch/cancel, phone transfer/cancel, monitor sends, all nine workspaces,
  greedy swaps, three layouts, native floating drag/resize/sink, five hotplug
  cycles, changed-resolution last-monitor reconnect and a new native launch
  afterwards. The run is diagnostic-only on the mounted product override;
  native captions/controls are not yet the replacement Wonad shell, and this
  is not final shell or container qualification.
- APK-owned launcher/panels, replacement decorations and move/resize, generic
  workspace policy, phone-side trusted confirmations, Linux-profile pixel
  parity, and final matched OS/APK/container qualification are unfinished.
- The client launcher APK and test APK compile, APK lint passes, and five new
  catalogue/UI-selection unit tests pass. The security probes now cover all
  twelve session methods, including synchronous catalogue reads. The host
  suite passes 672 tests (one skipped) with the framebuffer-test venv. The
  corresponding OS build completes successfully; its immutable product is
  `out/client-launcher-product-12`. `out/client-launcher-native-12b/report.json`
  passes ordinary APK window/input ownership, rendered launcher pixels,
  keyboard launch/cancellation on both monitors, phone-home preservation and
  changed-resolution unplug/replug with the launcher open. The launcher retains
  `FLAG_SECURE`: guest screenshots redact it, so the pixel check reads the
  emulator's actual display framebuffer instead. This does not weaken the OS
  screenshot policy or provide a production capture endpoint. The test uses the
  diagnostic mounted-product runtime, not the final matched container.
  `out/client-launcher-legacy-compat-1/report.json` separately passes the new
  APK's fallback on the previous OS without the launcher capability.
  `out/client-launcher-matrix-12a/desktop-matrix/report.json` also passes the
  three-monitor matrix. The expanded phone test exposed a real duplicate
  Activity: launching an existing phone app reused its task but created a new
  Activity inside it. Product13 binds the exact phone task/component/UID before
  consent, revalidates it afterward and transfers it without a launch intent.
  `out/client-launcher-native-13a/report.json` passes mouse Cancel, Escape,
  keyboard Enter, secure SystemUI-only phone windows and native focus, exact
  Task/Activity preservation, key isolation, expiry, removed-task rejection,
  ambiguous-task rejection and changed-resolution hotplug.
  `out/client-launcher-matrix-13a/desktop-matrix/report.json` passes the complete
  three-monitor legacy-policy matrix on that fix. Commands are
  `tools/client_launcher_smoke.py` and its `--desktop-matrix` variant; run them
  with the existing `out/x11-test-venv/bin/python3` framebuffer decoder. Both
  explicitly keep full-shell acceptance not passed.
- The separate v3 SDK/Rust/JNI implementation passes 89 core and 10 JNI tests;
  its authority has no workspace fields. APK shell geometry/gesture tests and
  its diagnostic build/lint pass. Native window/input integration, full-monitor
  border rendering, the shared Elric profile and v3 service are being integrated.
  These source/build checks are not yet live v3 OS/APK or container acceptance.
- Product15 built successfully. Immutable APK3 in
  `out/native-shell-apk-3/` passes 51 APK and six SDK JVM tests, release lint
  (zero errors, seven warnings) and release assembly. The broker adapter also
  compiles against the regenerated v3 SDK/private WM shim. These are compile
  checks, not runtime qualification of that pair.
- Fresh enforcing native runs `out/native-shell-native-15{a,b}/report.json`
  both remain not passed. Run15a booted in 50 seconds but stopped on a strict
  parser mismatch: InputDispatcher uses a hex-prefixed observer name, not the
  window-dump grammar. The corrected parser still requires the exact fixed
  shell Activity, UID, SPY/trust/nonfocus flags and full-monitor region. Run15b
  confirms all three live observers and acknowledged native shells, but stock
  `ActivityRecordInputSink` beneath the raised transparent shell swallows
  desktop clicks. No ordinary external mouse-focus success is claimed.
- Product16 built successfully and is frozen in `out/native-shell-product-16`,
  including the boot images and unpacked framework/SystemUI/native libraries.
  It includes exact-plane sink passthrough, nonfocusable shell Tasks,
  actual native empty-desktop pointer focus, explicit-minimum-only sizing,
  multi-monitor undock and restart/redock identity metadata. It also routes
  authenticated runtime-permission Activities to distinct phone Tasks without
  breaking `ActivityResult`, blocks native mutation during protected UI, and
  uses a pixel-free native input consumer to preserve phone prompt focus.
  CAMERA/location allow/deny callbacks, final-monitor recovery, physical X11
  hover/Meta gestures and the final matched image are still required.
  Its fresh preliminary run is `out/native-shell-native-16a`; it is not final
  shell qualification. It proves ordinary empty-desktop focus and the first
  keyboard app launch, but fails at the second fixture app (the fixture lacked
  its normal launcher entry). Its logs also expose independent stock freeform
  fallback interference: Android reparents the first native app into a desk,
  causing malformed hidden-focus observations and session churn. Fixture2 adds
  the genuine second launcher entry without changing app/task behavior.
  Product17 built the later immediate protected-input
  barrier, bottom-of-phone undock reparenting, and separate v37 location-button
  permission routing. Product18 additionally built sticky-ownership guards for
  immediate/deferred stock fallback and its animation handler, plus strict
  visible/input-eligible native focus reporting. Its immutable product is
  `out/native-shell-product-18`; both independent fresh18a runs failed before
  app launching, exposing Home occlusion/lifecycle and stale preferred-root
  keyboard-focus bugs. Product19 built the exact authenticated native Home
  background exemption and withdrawn-root focus-cache fixes. Both fresh19a
  runs preserve the shell through keyboard app launching but fail exact border
  pixels, before hotplug/security probes; rendering versus the patched SDK
  framebuffer capture pipeline is under investigation. The known-failing18
  candidate is diagnostic only, not a qualified Mournblade image.
  The host suite passes 867 tests (one skipped), including seven
  isolated permission-routing/compiled-helper and fourteen native-glue guards.
- `container/build-native-candidate.py` creates only explicitly unqualified
  `wonad:native-v3-candidate-*` bundles. Strict Phase 1 packaging accepts only
  immutable base
  `sha256:0bf80454dbaa59bacd955d3e0140d8c91c4dcbd4d6e3e941274cdf10cb374b3f`
  with its reviewed manifest and exact
  unqualified labels, removes both inherited candidate namespaces, then restores
  only the reviewed StyX/grsh support allowlist plus fresh product, client and
  build-evidence files. The packet's immutable, hash-bound `apksigner` tools
  independently prove that the exact receipted finished `SystemUI.apk` and fault
  APK share the packet's development platform signer; their raw transcripts are
  included in the candidate's verified inventory. It cannot publish a release
  tag and rechecks that its unqualified output tag is absent immediately before
  publication. Docker provides no compare-and-swap tag primitive, so the local
  candidate-tag namespace must remain quiescent during that final check/tag
  interval. The separate native qualification and multi-monitor auditors keep
  evidence separate and reject missing native security/functional ports; see
  `NATIVE-ACCEPTANCE.md`. Source-gate success is not release qualification.

Acceptance must exercise the actual final image: keyboard launches and text,
exact Recents transfers, tiling/floating/workspace behavior, mouse operations,
multiple screens, changing resolution, unplug/replug, phone isolation, crashes,
freezes, locks, user switches, stale sessions and recycled native IDs. Capture
pixels as well as native task/input observations. Keep baseline, diagnostic and
candidate evidence distinct; earlier reports do not qualify a changed image.

## Historical OS-glue review checkpoint — 2026-10-09

At this historical checkpoint the deployment target was Pixel 10; the x86-64 emulator remained
the test target. This checkpoint is a bounded source/model review, **not** a
security certification or matched-image release acceptance. The historical
campaign notes above retain their original scope.

Reviewed boundaries: broker UID/user/current-signer admission before and after
executor dispatch; bounded/lossless Rust/JNI scalar decoding; native task/UID
and display-incarnation identity; sticky display containment; explicit phone
confirmation; readiness/input routing; generation/revision/deadline completion
and the native committed-transaction/input-report fences. Existing production
network and credential handling remains outside the privileged extension.

**Historical API2 finding (the API2 implementation has since been deleted):**
`FutureTask.cancel(false)` can discard the result of a session
open that has already started. The old cancellation callback only reconciled
the environment and could leave an orphan lease. Both API2 and API3 dispatch
paths now retain the executor-owned result and revoke only that exact abandoned
session. Cleanup is queued after the operation on the same Shell executor;
queued-but-unstarted work remains cancelled, and a replacement lease is never
revoked. Cleanup also runs when the timed-out operation finishes before
`cancel(false)`, and interrupted waiters preserve their interrupt status. Initial
launcher catalogues have exact-session/catalogue cleanup so an unreceived page
cannot leave shortcuts suspended until the picker deadline. Pagination never
disposes an existing catalogue. The compiled real-code test exercises 337
assertions, including 64 controlled running-operation races, deterministic
completed-before-cancel races, one-shot cleanup and nullable outcomes.
The SystemUI and system images compile successfully with the dispatch changes.
Review also found an API2 initial-picker exception path that left its ticket
and shortcuts live until the watchdog. Exact-owner cleanup now covers that
path, with 15 compiled assertions checking error identity and replacement
picker/lease preservation. Its focused real-framework compile passes; the
matched OS rebuild is still pending.
Live concurrent Binder cancellation and exact-image release qualification
remain outstanding; compilation is not evidence of those runtime guarantees.

The review-candidate SDK baseline records all 21 AIDL files, ordered method and
parcel declarations, leading type annotations (including Binder `Descriptor`),
directions/nullability/oneway annotations, constants and
capability values. `tools/sdk_contract.py` and hostile-change tests detect
unreviewed changes. `platform/stage-os.py` checks it before modifying the OS
checkout. It is deliberately not an automatic baseline updater or evidence of
runtime behavior; approved future additive capabilities require explicit review.

Measured from the owned stage after this fix (physical lines, including retained
API2 and shared wire constants; excluding generated AIDL):

| Staged source | Files | Lines |
| --- | ---: | ---: |
| Rust | 20 | 4,986 |
| Kotlin | 30 | 6,619 |
| Java | 0 | 0 |

The separate applied framework hooks are not zero Java: the pinned framework
worktree has 612 inserted / 23 deleted production Java lines across 28 files,
plus Java test additions. Those are diff-line counts, not a count of the full
Android framework. Existing framework Kotlin hooks, Launcher3 changes and
generated Binder code are additional surface. Authentication/transport work
must not add privileged OS code. These totals make the review scope explicit;
they do not justify describing the complete extension as a tiny shim.

Passing checks at this checkpoint: Rust broker core and broker/input JNI tests,
clippy for the broker core, 76 compiled native-boundary regressions, 28 native
contract tests, 13 SDK-baseline adversarial tests and OS staging safety tests.
The latest 17 broker Kotlin sources also compile against the real pinned
framework/Shell classpaths. A fresh run of all 605 native acceptance-auditor
tests passes; these validate the audit/test machinery, not a new guest image.
Remaining review obligations include live concurrent Binder cancellation,
SystemUI/native revocation ordering under failure, APK-only upgrade compatibility,
and all exact-artifact security/hotplug/input/pixel/soak release gates. No previous
runtime report is promoted because these source/model checks pass.

## Authoritative Phase 1 OS-glue/interface checkpoint — 2026-10-11

This checkpoint supersedes earlier present-tense API and build statements in
this document. It records source, compile and staging evidence, not a release,
security certification, completed emulator qualification or physical-device
result. There is no flashable Phase 1 image yet.

### Frozen APK-facing boundary

The sole public desktop interface is the neutral
[`org.wonad.desktop.api` v3 contract](desktop-sdk/API-v3.md). API2 has been
removed from the SDK and OS glue. `API_VERSION` is exactly 3 and
`openSession` rejects every other value. The public tree contains 12 AIDL files
and none of the removed `openNativeSession`, `IDesktopNative*`,
`NativeDesktop*`, `NATIVE_API_VERSION`, `CAP_NATIVE_*` or `MAX_NATIVE_*`
symbols. Internal implementation names may still use “native” to distinguish
the OS adapter; those names are not APK ABI.

The machine contract gate passes against
[`desktop-sdk-contract-v3.json`](tests/fixtures/desktop-sdk-contract-v3.json).
Its canonical contract signature is
`db6ac649c34d8c25ab0bdd4a46802639deb3972d376070c6c3cdd811d7962fff`;
the baseline JSON file itself has SHA-256
`519893e53906548144f5f407de0481f21d6b608f32cf53ffa658f28c1f235e8c`.
The canonical historical 3.0.0 publication coordinate is
`org.wonad:desktop-sdk:3.0.0`. Two independent builds produced identical
primary artifacts (Maven timestamp metadata is expected to differ):

| Published artifact | SHA-256 |
| --- | --- |
| `desktop-sdk-3.0.0.aar` | `c1e164b7c57efd7f0997a90c92707cdaca16d1e5d3a47eb61197eb7b14fc4b07` |
| `desktop-sdk-3.0.0-sources.jar` | `85d185c6c554d3f578c0961fecd007c67f98cb121390295c209843702eb7ae37` |
| `desktop-sdk-3.0.0-contract.zip` | `ceb247ebddcbb97bfb085deaa5aa5314e143e4918978eb4f8b5ba5354cecbb5f` |
| `desktop-sdk-3.0.0.pom` | `b519f9fb748dd17a02a220fdf1cbb0baab3a9a3dbd85c24895db1582c5ed32d0` |
| `desktop-sdk-3.0.0.module` | `50f709c0361e15c38365eda0a488043f7fbdbffc6b09aa64e7b92489177c5099` |

SDK 3.0.1 is a documentation-only patch over this unchanged API-v3 machine
contract. Its source describes the process-global picker cadence and the
nullable/one-way outcome boundary; it adds no Binder, AIDL, JVM or numeric
surface. No 3.0.1 artifact hash is stated here before two independent exact
publication builds agree. Fresh source, stage, client and release evidence must
bind the resulting `org.wonad:desktop-sdk:3.0.1` artifacts and the normative
`API-v3.md` contract member. The table above remains immutable 3.0.0 history.

The boundary remains deliberately narrow. The OS authenticates the active
user, ordinary UID, exact package and one current signer; resolves opaque
task/display identities; applies bounded focus, placement, visibility and
close operations; owns revocation and fail-black behavior; and presents
trusted phone-side selection. Wonad owns workspaces, layouts, borders, panels,
launcher presentation and keyboard/mouse policy. StyX11, grsh, Kerberos and
Bifrost do not bind this SDK and add no privileged OS API.

### Pinned source and reviewed platform surface

The current pin is GrapheneOS `2026100600` for Pixel 10 (`frankel-cur-user`,
ARM64), with `sdk_phone64_x86_64-cur-userdebug` as the development sibling.
The release pin is unchanged by the retarget. Prior Frankel vendor, source-port,
glue-review and build evidence retains its original hashes and paths and is not
current Pixel 10 qualification. Frankel build/vendor/OTA tools now select the
physical target; the emulator remains a separate x86-64 development lane.
The authenticated lock is [`grapheneos.lock.json`](grapheneos.lock.json): its
manifest commit is `26f7e8a760d4343a501faf09773ec4cc61a6b56b`, framework
commit `84183aff99be5e156dc0446a6fa2d4a7150f4bc3`, Launcher3 commit
`47accce386f2abdc84e87c05b5587be6e0b0854f`, and Goldfish commit
`1facfe03b3519c3413a51d2ea56400bbade0b4c3`.

The exact builder image is
`sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33`.
Its verified
[`phase1-builder-provenance-live-1.json`](out/phase1-builder-provenance-live-1.json)
has SHA-256
`6b46d1bb181d2168a80c900a789423e717d7c1e46c71792b28d2d5d39a34bd46`.
The dedicated baseline source checkout is exact at the signed manifest pin.
The initial custom-checkout review passed the schema-4 verification gate
(`stage-os.py --verify-only`) with 54 staged files, but that checkout predates
the two freeze fixes recorded in
[`OS-GLUE-REVIEW-2026100600.md`](platform/OS-GLUE-REVIEW-2026100600.md) and is
historical evidence only. The corrected custom7 checkout now has a verified
57-file stage: 40
ordered framework patches covering 53 owned targets, four Launcher3 patches
covering nine targets, and two Goldfish patches covering two targets. A fresh
custom build and comparison remain pending. The actual stage marker at
`../wonad-grapheneos-2026100600-phase1-custom-7/external/wonad/.wonad-stage.json`
has SHA-256
`5fb1f000c37ab702bbd2722d4dde6d1936d792533d2e76798e8ce59e271c0d5d`.
Root and an independent agent verified all 57 file hashes, 64 platform-target
hashes and 46 ordered patch hashes. This is source/staging proof, not a binary
or runtime pass; see the
[preparation record](out/phase1-custom7-source-preparation-20261011-1.md).

The historical custom6 continuation was intentionally stopped during source preflight on
11 October at 12:56:42 UTC, before compilation or creation of a build container
or OUT. An actual extracted Kotlin regression reproduced newly populated
ordinary app input admission on a claimed monitor without a valid lease.
The reviewed workspace fix adds/restores only Wonad-owned `DROP_INPUT`, leaving
stock-owned flags intact. Final NativeBridge SHA-256 is
`3fd2bd1317217220a5efbb4118f7fc762f7dd32d784b712c5ff1020e2221248c`;
root's final focused compiled/safety suite passes 17/17. It changes neither
the public SDK nor the private IPC surface. The separate custom7 checkout
passed all 1,057 clean tracked-project checks before staging, exact stage/SDK
verification, and 60 staging/platform/SDK host tests. Its fresh continuation
started at 13:13 UTC; its full source preflight passed and its compiler
container started at 13:24:44 UTC. No corrected successful build or guest
qualification is claimed. Independent inventory confirms only
NativeBridge differs from custom6. The following owned-language inventory is
custom7; the unchanged platform diffs retain their prior counts.

The required current 57-file `external/wonad` stage comprises 14 Rust files, 26
Kotlin files, 12 AIDL files, two XML files, one Soong file, one license and one
DER public certificate. The count includes the generated signer pin and
contains no owned Java. It describes the staging contract's production inputs,
not a completed build or the adjacent APK and unit/instrumentation test trees.
The staged production code has these physical line/byte counts (not semantic
complexity or a measure of the rest of Android):

| Language | Files | Lines | Bytes |
| --- | ---: | ---: | ---: |
| Rust | 14 | 3,269 | 101,732 |
| Kotlin | 26 | 6,176 | 344,785 |
| AIDL | 12 | 167 | 6,085 |

The ordered staged `path\0sha256\0size\n` ledger has SHA-256
`23f065469a1783f7191c988f45329cea83ca5f6c2da2d82dc8c113dff8b5c805`.

“Zero owned Java” does not mean the platform patch is Java-free. Relative to
the pinned upstream commits, production framework/SystemUI/WM Shell changes
touch 28 Java files (628 insertions, 26 deletions), while Launcher3 changes
touch three Java files (55 insertions, five deletions). The platform also has
Kotlin, AIDL, XML and build-file changes. These are diff-line counts, not the
complete size of the Android classes, and all of them remain part of the
privileged review surface.

Across all staged platform production targets, the diff is 62 files with
1,277 insertions and 55 deletions; the two framework test targets add 208
lines. These totals are relative to the exact pinned revisions, not cumulative
patch-file additions. The private cross-process surface in that recorded source
inventory is:

- Fourteen SystemUI-to-WMS `IWindowManager` methods for shortcut/focus/UI
  leases, focused display, task/display observations, normal/signed frame
  application and completion, task operation/transfer, ownership, identity
  epoch and protected-interaction observation. WMS requires the exact SystemUI
  UID and `STATUS_BAR_SERVICE`; these are not ordinary-APK APIs.
- Two Launcher3-to-WM Shell Recents methods, `canSendTaskToWonad` and
  `sendTaskToWonad`, with exact Launcher UID and live-task identity checks.
- Seventeen scalar-only JNI entry points: eight broker/Rust and nine
  input/Rust entry points. Android task/display/Binder object handles do not
  cross JNI.

Stock-UI suppression is separately mapped to the sticky WMS display claim:
WM Shell desktop policy, roots and decorations; SystemUI status/navigation
bars, privacy dots and external edge-back input; Launcher3 external taskbars;
and framework wallpaper, home, IME, permission routing and input lifetimes.
The phone remains outside that claim. This is a bounded source inventory, not
proof that those branches have executed on the replacement image or a final
approved release review.

The current working-tree staging contract additionally contains the reviewed
`wonad-authoritative-focus-framework.patch` and
`wonad-authoritative-focus-launcher.patch`. Those patches add six Kotlin files
and a private appended `IShellTransitions.requestFocusedDisplay` transaction
(11); they do not modify the neutral desktop SDK or confer ordinary APK
authority. The caller must hold `MANAGE_ACTIVITY_TASKS` before Binder identity
is cleared. WM Shell uses the existing SystemUI-only WMS focus observation on
one process-global, zero-queue worker, checking the caller's active user before
and after the observation. Launcher accepts only exact token/types/deadline and
fresh connection identity on MAIN, then rechecks unlocked state and display
eligibility before queued command effects. A hung query/callback retains its
single slot rather than spawning replacement workers. This is a bounded
asynchronous observation, not an atomic snapshot across future user/focus
changes or rollback of already-committed UI work.

Normal unguarded phone commands retain their original stock focus fallback and
continuation semantics. The integrated source-bound host suite compiles 1,158
actor/worker assertions and 24 side-by-side stock/guarded method checks, and
reconstructs the full owned patch sequences without changing the OS checkout.
It does not prove Android Binder/Looper behavior, platform compilation, or
successful phone Recents. The quantitative inventory above describes the
recorded custom7 stage; regenerate it for the next complete source freeze,
including the pending keyboard-containment changes. No previous source marker,
image or runtime receipt has been updated or requalified by these patches.

### Current development artifacts and checks

Two matching API-publication successor compiles are
[`-13`](out/native-current-successor-12-phase1-v3-20261010-13/build-receipt.json)
and
[`-14`](out/native-current-successor-12-phase1-v3-20261010-14/build-receipt.json).
Their build-receipt SHA-256 values are respectively
`3f789c925172fcdec968008d84d6b88c7a0365ee76758d3b5b1d8a7032c7d722`
and
`1299db854c93f9bf946c1d3a28dddd1ef3cb4a5a39211d6c5aeba9b3bd737dfb`;
their source-freeze SHA-256 values are respectively
`849a76892692daaee6e31a3ff74300e16919e7fd43a37e03d889bb8fe21f5c27`
and
`22a2b849c8f5d05b928cae802bd6fa52e9362152c34ed3bff4603da8d5a38106`.
The two source maps are identical and contain only the neutral API3 public
surface (internal implementation names remain non-ABI).
These are compile records, not runtime results; build packaging/signing bytes
outside the frozen publication payload need not make the enclosing APK or
receipt byte-identical.

The current development client packet prepared for the source-matched x86
sibling is
[`phase1-emulator-client-packet-20261011-3`](out/phase1-emulator-client-packet-20261011-3/receipt.json);
its receipt SHA-256 is
`986f00bcebc7e215200621eac6bbbc2c580a2617759700106f0cba9d1c8abfad`.
It binds the runtime-capable successor
[`-15`](out/native-current-successor-12-phase1-v3-runtime-20261011-15/build-receipt.json),
whose build receipt has SHA-256
`dc779ae995c96528ff8548b85ff333a6b13a0ba169ba810189c87474f62a3e10`.
The packet's Wonad/conformance certificate digest is
`3183261f28256159ad5e488d8a34854e77f36e14348720daae7f8cae7a8c26ff`.
It is explicitly a development identity, not the production signer. Its
version-12 Wonad APK SHA-256 is
`7494132416df3b4957ca944bdf5657be3d6e1df2a6eca74833462702d4d1e2ac`;
the separately selected minimal conformance APK SHA-256 is
`a38b3570ec0b0629e55682a5b6ff608efdf82568b8f406d90c7569c1c113603b`.
They deliberately share package identity and are mutually exclusive clients.
The packet also freezes and compiles the update-data canary and its
session-security APK; that APK's SHA-256 is
`5305078caa267578570e26b2cc5520598606acceaeaf12862cd2da4c14d84b1c`.
The packet says `runtime_qualified: false`, `production_identity: false` and
`source_matched_image_pending: true`; its successful compile/tests do not
promote it to a runtime result.

The independently audited
[`custom7 wrong-signer bundle`](out/phase1-evidence-custom7-5/preparation/wrong-signer/signing-receipt.json)
has receipt SHA-256
`e7a62b21aee333bdc0cd267b633db756b7a3e720c65d300ec0aa2ecd250a4d87`.
It is a signature-only derivative whose receipt says
`runtime_qualified: false`; it is input for a future negative runtime gate,
not evidence that the rejection path has run on the source-matched image.

The current evidence formats are source-provenance schema 5, x86
build/comparison receipt schema 4, and ARM64 build/comparison receipt schema
3. The Wonad stage marker remains schema 4; these numbers describe different
records and are not interchangeable. This names the accepted formats, not a
successful current x86 pair or Shiba receipt. Host tests and offline
verification validate the review/build machinery and frozen inputs. They do
not replace Binder fault injection or execution of the finished image.

The 12 October tool integration additionally supports a manifest-authenticated
`frameworks/native` lane. Selecting a reviewed native patch requires stage
schema 5 and exact native revision/patch/target inventories across every
consumer; the registry is currently empty, so schema 4 remains active.
Checkout/project/manifest ancestors reject symlinks, scratch patch replay owns
an isolated Git root, and target inventories match the registered patch union.
Build/delta/guest evidence now explicitly binds `libinputflinger.so` and
`libandroid_servers.so`. The
[root tool review](../../wonad-phase1-build-evidence/phase1-native-stage-root-integration-20261012-1/root-review.json)
records 249 passing host regressions plus 15 current-method schema controls.
No native keyboard patch, fresh schema-5 OS build or new runtime qualification
is implied. Private event lifetime, stock phone behavior, exact admitted target
and balanced cancellation remain implementation/runtime obligations. Broader
reader/subdevice and safety-realm prototypes are retained research, not automatic
Phase 1 blockers or changes to normal phone keyboard use.

### Honest remaining Phase 1 gates

- Complete and authenticate the unmodified/custom source-matched x86-64
  builds, compare their receipts, build an immutable custom candidate, and run
  the conformance APK from a fresh guest. No completed baseline/custom binary
  comparison or current-image runtime pass is recorded at this checkpoint.
- Run the full fault matrix: concurrent Binder cancellation and timeout,
  callback/commit/topology failures, no/missing/wrong/updated clients, lock and
  user transitions, SystemUI/client death, stale/recycled identities, phone
  regressions, external UI/input containment and Recents transfer.
- Pass three independent clean boots with three mixed monitors and 20 populated
  hotplug cycles per boot, then the separate uninterrupted 24-hour soak defined
  in [`PHASE1-RUNTIME-QUALIFICATION.md`](PHASE1-RUNTIME-QUALIFICATION.md).
- Finish the ARM64 `frankel-cur-user` build and same-pin upstream comparison,
  then produce factory, target-files, full OTA and authenticated incremental
  predecessor-to-successor artifacts. Emulator execution is not execution of
  the Pixel 10 binaries.
- Supply protected, distinct production Wonad and GrapheneOS AVB/OTA/factory
  signing identities. The current emulator certificate is not eligible.
- Choose a project-owned HTTPS update URL/channel, predecessor release and
  operational owner, then bind source, tools, SDK, client, signer and output
  hashes into production provenance and offline-verification receipts as
  specified in
  [`PHASE1-PROVENANCE.md`](platform/PHASE1-PROVENANCE.md).
- Phase 2 must still install and qualify the exact Phase 1 hashes on a physical
  Pixel 10. That hardware work is intentionally not claimed by Phase 1.

Until those gates pass, the frozen API and reviewed source are useful inputs,
but no image described here is a production release or a flashable,
hardware-qualified Pixel 10 OS.

