# Wonad external-desktop API v3 — SDK documentation 3.1.0

Status: additive shortcut-key/client-prompt candidate, not runtime qualified.
The machine-readable companion is `desktop-sdk-contract-v3.1.json`, with
canonical signature
`0182df553005ed145288380526f40f593763573d458f8147970840d973d13adf`.
The immutable 3.0.0/3.0.1 publications and their original baselines are retained.
The AAR supplies types only. It installs no service, permission, authority or
desktop policy. This document alone creates no artifact, release, runtime
qualification or compatibility claim. Publication identity is established only
by a separately built and independently verified Maven repository and its
release evidence.

This version appends three session operations and one parcel type, two capability
bits, a finite control-key command and its scalar validation helper. All prior
wire layouts, methods, offsets and constant values remain unchanged. The
additive source/JVM compatibility audit is separate from runtime qualification.

## Fixed identity and endpoint

- Client package: `org.wonad.desktop`.
- Broker action: `org.wonad.desktop.BIND`.
- Broker component:
  `com.android.systemui/org.wonad.desktop.broker.WonadBrokerService`.
- Consent setting: `Settings.Secure.wonad_external_desktop_enabled`, per user.
- Client consent component:
  `com.android.systemui/org.wonad.desktop.broker.WonadClientSettingsActivity`,
  guarded by `org.wonad.desktop.permission.OPEN_OS_SETTINGS`.
- Shell diagnostics consent component:
  `com.android.systemui/org.wonad.desktop.broker.WonadSettingsActivity`, guarded
  by `android.permission.DUMP` and restricted to root/shell on debuggable builds
  (or same-UID/system initiation).
- Fixed client activities: `.ExternalHomeActivity`,
  `.ExternalShellActivity`, `.LauncherActivity`, and `.DesktopPromptActivity`.
- The four fixed activities are exported with
  `android.permission.STATUS_BAR_SERVICE`. The shell receives long extras
  `org.wonad.desktop.shell.GENERATION` and
  `org.wonad.desktop.shell.DISPLAY_TOKEN`. The launcher receives long extras
  `generation` and `catalog`.
  The client prompt receives `generation` and `request`; its process-private
  contents are not supplied by or trusted as OS policy.

The OS admits only an ordinary application UID owned solely by the exact
package, in the active user, with one current APK-content signer matching the
certificate digest compiled into the OS. Shared UIDs, platform signing,
multiple signers, signer lineage, a foreign package, an inactive user and
signer substitution are rejected. `getApiVersion` and `getCapabilities` still
authenticate the caller. `openSession` additionally requires consent, an
interactive unlocked phone and at least one eligible monitor.

The client consent permission is `signature|knownSigner`; its known certificate
digest is generated from the same public DER certificate that pins broker calls.
The activity also rechecks the launcher's active-user UID, sole package and
signer identity. The permission grants no broker or WMS authority. It only lets
the pinned APK foreground the SystemUI-owned consent UI, whose secure setting
changes still require an unobscured explicit click by the current unlocked
user. Ordinary applications cannot launch either consent component.

An eligible monitor is a live, on, trusted, secure, non-private external or
virtual display other than display zero. At most `MAX_DISPLAYS` are exposed.
The phone is never a destination.

## Version and evolution

`API_VERSION` is exactly 3. `openSession` rejects every other value. Maven
version 3.1.0 adds opt-in capabilities without changing API-major negotiation.
SDK 3.0.1 remains a documentation-only patch of the original machine contract. Removed draft-v2
capability bits 0, 1, 2 and 4 remain permanently reserved. Existing constants,
parcel fields and Binder methods keep their numeric values and order.

Compatible v3 evolution is additive only: append a Binder method, capability
gate behavior which cannot safely default, and add parcel data only when old
readers receive a safe default. Removal, reorder, reinterpretation, type or
unit changes, incompatible bounds, and reuse of a reserved value require a new
major API. The published contract archive freezes AIDL order, constants and
generated Binder transaction offsets.

The frozen limits and timers are `MAX_TASKS=128`, `MAX_DISPLAYS=9`,
`MAX_COORDINATE=32768`, `MAX_SHELL_REGIONS=768`,
`MAX_LAUNCH_PAGE=128`, `MAX_LAUNCH_ENTRIES=4096`,
`HEARTBEAT_INTERVAL_MILLIS=1000`, `CLIENT_TIMEOUT_MILLIS=5000`,
`TRANSACTION_TIMEOUT_MILLIS=15000`, and
`LAUNCHER_TIMEOUT_MILLIS=30000`. The exact capability values are:

| Capability | Value |
| --- | ---: |
| `CAP_SHORTCUTS` | 8 |
| `CAP_TRANSFER_PICKER` | 32 |
| `CAP_EXTERNAL_UI` | 64 |
| `CAP_APK_LAUNCHER` | 128 |
| `CAP_FRAME` | 256 |
| `CAP_SHELL` | 512 |
| `CAP_SIGNED_PLACEMENT` | 1024 |
| `CAP_SHORTCUT_KEYS` | 2048 |
| `CAP_CLIENT_PROMPT` | 4096 |

### SDK 3.1.0 shortcut keys and ordinary client prompt

- `getShortcutProfile(generation)` is synchronous and nullable, with the same
  authenticated owner/generation and bounded dispatch rules as other reads.
  It returns `DesktopShortcutProfile { keysetVersion=1, requiredModifiers }`.
  Modifiers are Android aggregate bits: 69632 (Ctrl+Super) for emulator products,
  65536 (Super) for Pixel 10. This descriptor is not authority. Product selection
  is explicit at build time, not inferred from the CPU ABI.
- `enableShortcutKeys(generation, enabled)` requires `CAP_SHORTCUT_KEYS` and is
  mutually exclusive with legacy `enableShortcuts`. Disabling either leaves
  no active key mode. Legacy commands 1..16 and their bindings are unchanged.
- Only opted-in sessions receive command 17 (`COMMAND_SHORTCUT_KEY`). Its
  argument is `(AndroidKeyCode << 1) | shifted`, with shifted exactly 0 or 1.
  Both Shift variants are admitted for 1..9, W/E/R, J/K, Space, Enter, equals
  and slash. Unshifted H/L/N/S/minus and shifted C/semicolon complete the set.
  `DesktopShortcutKeys.valid` defines the exact finite alphabet. No application
  text, arbitrary key registration, timing, device identity, repeats or releases
  are delivered to the APK. Focus/user/trust/lease checks and exact captured
  release draining remain mandatory. Desktop action meanings belong to the APK.
- The chosen product prefix also gates modified mouse gestures in the new mode;
  unmodified client input and legacy-mode pointer behaviour stay unchanged.
- `showClientPrompt(generation, requestId, displayToken)` requires
  `CAP_CLIENT_PROMPT`, a positive process-private request ID and a ready secure
  monitor. It is a one-way, fire-and-forget request, not a frame transaction;
  no `onResult` is emitted. It starts only the pinned ordinary APK's fixed
  `.DesktopPromptActivity` with the fixed system launch permission. It never
  accepts arbitrary components, text, workspace data, commands or handles.
  The APK owns prompt contents, cancellation and a 30-second UI deadline.
  Native focus/layer containment and detach cleanup cover this fixed role just
  like the launcher. The prompt is not trusted system consent/confirmation and
  grants no phone-task transfer authority.

Result values are `APPLIED=0`, `STALE=1`, `INVALID=2`, `UNSUPPORTED=3`,
`REVOKED=4`, `BUSY=5`, and `PLATFORM_CONSTRAINT=6`. Revocation values are
`DISABLED=1`, `UNDOCKED=2`, `LOCKED=3`, `USER_CHANGED=4`,
`CLIENT_FAILED=5`, and `IDENTITY_CHANGED=6`. Command values are, in order,
`FOCUS_NEXT=1`, `FOCUS_PREVIOUS=2`, `SWAP_NEXT=3`, `SWAP_PREVIOUS=4`,
`SHRINK_MASTER=5`, `EXPAND_MASTER=6`, `NEXT_LAYOUT=7`, `VIEW_WORKSPACE=8`,
`MOVE_TO_WORKSPACE=9`, `CLOSE=10`, `SINK=11`, `LAUNCH=12`,
`TOGGLE_FLOATING=13`, `TRANSFER=14`, `FOCUS_MONITOR=15`, and
`SEND_TO_MONITOR=16`.

Binder methods are assigned from `FIRST_CALL_TRANSACTION` in this immutable
order: broker — `getApiVersion`, `getCapabilities`, `openSession`; callback —
`onSnapshot`, `onCommand`, `onResult`, `onRevoked`; session — `applyFrame`,
`focusTask`, `closeTask`, `enableShortcuts`, `heartbeat`, `release`,
`enableExternalUi`, `showShell`, `launcherPage`, `showLauncher`,
`selectLauncher`, `showTransferPicker`, `applySignedFrame`. The offsets and
ordered argument declarations are also present in the machine baseline.

The frozen parcel field order is:

| Parcelable | Fields in wire order |
| --- | --- |
| `DesktopRect` | `left`, `top`, `right`, `bottom` |
| `DesktopDisplay` | `token`, `displayId`, `bounds`, `densityDpi`, `secure`, `shellGeneration`, `identityHint` |
| `DesktopTask` | `token`, `displayToken`, `bounds`, `minimumWidth`, `minimumHeight`, `resizable`, `visible`, `inputEnabled`, `zOrder`, `title`, `packageName` |
| `DesktopPlacement` | `token`, `destinationDisplayToken`, `bounds`, `visible`, `inputEnabled`, `zOrder` |
| `DesktopShellRegion` | `generation`, `displayToken`, `bounds` |
| `DesktopFrame` | `topologyRevision`, `focusedDisplayToken`, `focusedToken`, `placements`, `shellRegions` |
| `DesktopSnapshot` | `generation`, `revision`, `topologyRevision`, `capabilities`, `displays`, `tasks`, `focusedDisplayToken`, `focusedToken`, `identityEpoch`, `interactionBlocked` |
| `DesktopLaunchEntry` | `index`, `label`, `component` |
| `DesktopLaunchPage` | `generation`, `catalogId`, `displayToken`, `offset`, `totalEntries`, `expiresAt`, `entries` |

Integers are signed 32-bit values, longs are signed 64-bit values, booleans are
AIDL booleans, strings are nullable UTF-16 Binder strings, parcel references
and arrays use the nullability generated by the published AIDL, and
`launcherPage` alone has a nullable return. No unspecified field carries
authority.

## Units, identity and ordering

All rectangles are physical display pixels with exclusive right and bottom
edges. A rectangle has positive width and height. Coordinates and dimensions
are bounded by `MAX_COORDINATE`; `applyFrame` additionally requires placement
inside its destination monitor. Only capability-gated `applySignedFrame` may
request a finite partially or wholly off-screen task rectangle. Shell regions
always remain inside their display.

Generation identifies one authenticated lease. Revision identifies one
published task/display state within that lease. Topology revision identifies
the monitor set. A request must use the current generation, base revision and
topology revision. Request IDs and heartbeat sequences are positive,
monotonically increasing within the lease. One state-changing request may be
pending; later concurrent work receives `RESULT_BUSY` or becomes stale.
On the currently live session Binder, a positive, strictly newer request ID
paired with the wrong generation completes once as `RESULT_STALE` under the
live generation. Nonpositive or replayed request IDs, calls through a retained
terminal/replaced session Binder, and wrong-generation calls without a request
ID are inert. Queue-overload results pass through the same native request
admission and sequence state as normally queued requests.

Task and display tokens are opaque OS identities, scoped to the active user
and `identityEpoch`. They are not Android task IDs, display IDs, Binder
handles, surfaces or input channels. They are never client-created authority.
`identityEpoch` survives APK and SystemUI restart and changes with the
system-server identity namespace. `identityHint` is an opaque physical-display
continuity hint, not authority. Clients must discard tokens on epoch, user or
generation change and must not infer structure from their values.

Displays and tasks are sorted deterministically by token. Placements form a
complete one-to-one set for all observed tasks. Their `zOrder` values form the
unique sequence `0..taskCount-1`, with larger values above smaller values.
Visible and input-enabled are equal; a hidden task receives no input. A focus
pair of zero/zero retains focus. A nonzero display with zero task focuses its
empty desktop. A nonzero task must be visible on the named display.

## Broker and lease

`getApiVersion()` returns 3. `getCapabilities()` returns the currently usable
capability mask; a missing optional native integration clears its bit rather
than granting partial authority.

`openSession(3, callback)` creates the sole lease. The first callback is a
fresh `onSnapshot`. A second lease is rejected until the exact previous owner
is revoked. A call which times out or whose result is abandoned is cleaned up
as that exact owner and cannot revoke a replacement lease.

The client sends `heartbeat(generation, sequence)` at most
`HEARTBEAT_INTERVAL_MILLIS` apart. The OS lease expires after
`CLIENT_TIMEOUT_MILLIS`. `release` deliberately ends the lease. Consent loss,
lock/noninteractive state, active-user change, caller identity change,
heartbeat expiry, client death, an unrecoverable native failure or loss of the
eligible environment revokes it. Revocation parks every claimed monitor black
and consumes external input until a fresh authorized session establishes all
required planes; it never falls back to stock external Android UI.

`onRevoked` is terminal for its generation. Retained session Binders and late
callbacks are inert. Reasons are `REVOKED_DISABLED`, `REVOKED_UNDOCKED`,
`REVOKED_LOCKED`, `REVOKED_USER_CHANGED`, `REVOKED_CLIENT_FAILED`, and
`REVOKED_IDENTITY_CHANGED`.

## Snapshots and completion

`onSnapshot` is a complete bounded observation, not a delta. It contains no
workspace, layout, floating or panel policy. The APK itself is excluded from
eligible application tasks. Only ordinary running standard application tasks
owned by the active user are reported. Titles and package names are display
metadata, never identity.

`interactionBlocked` is true whenever the OS reserves interaction for trusted
phone-side UI. This includes broker-owned selection or confirmation, keyguard,
protected/system phone UI and a genuine permission request routed from a
managed external task to the phone. The value is derived from live OS state;
the APK cannot assert or clear it. Mutations during that state are stale, and
external focus/input cannot bypass the protected phone interaction.
`shellGeneration` is zero until the fixed authenticated shell Activity has
actually drawn on that display; mutation waits until every shell generation
equals the lease generation.

`onResult` completes one request ID with an actual post-transaction observation,
not a transaction ACK. Results are `RESULT_APPLIED`, `RESULT_STALE`,
`RESULT_INVALID`, `RESULT_UNSUPPORTED`, `RESULT_REVOKED`, `RESULT_BUSY`, and
`RESULT_PLATFORM_CONSTRAINT`. A platform-operation timeout or an unobservable
committed state reports a platform constraint and revokes the unhealthy lease.

## Picker admission and observability

The current API-v3 picker admission gate is one process-global monotonic clock
gate in the SystemUI broker native process. It is shared by launcher catalogues
(kind 1) and transfer pickers (kind 2), and is not scoped by session,
generation, user, display or picker kind. Its lifetime is the hosting process;
a process restart constructs a new picker and API v3 promises no cross-restart
cooldown continuity. A successful admission at monotonic time `T` advances the
earliest next admission to `T + 1000` milliseconds.
Attempts strictly before that boundary are rejected; an attempt exactly at the
boundary may be admitted if every other current condition is satisfied.

Cancellation, successful or invalid selection, catalogue consumption, picker
expiry, session release/replacement, generation change and display change do
not reset, shorten or extend that one-second gate. Clock regression, invalid
scope, an already-live picker, unsupported kind, excessive choices and native
identifier exhaustion can also reject admission. The 1000-millisecond rule is
therefore a necessary timing boundary after a successful admission, not a
promise that the next request will be accepted. A client-side delay does not
prove admission or identify a rejection reason.

`launcherPage` is synchronous and nullable. A null return means that no page
was admitted or continued for that call. It intentionally carries no reason;
among the possible causes are stale or invalid session/generation/display
scope, unavailable capability or environment, a live or cooling-down picker,
invalid catalogue continuation, expiry and bounded native failure. Binder or
security failures may instead throw. Clients must not interpret null as a
specific cause or busy-loop to manufacture admission.

`showTransferPicker` is a one-way, fire-and-forget request. Successful Binder
return proves delivery to the Binder transport only; it is not an acceptance,
visibility, catalogue, selection or cancellation acknowledgement. Rejection
may be silent to the caller. A later `interactionBlocked=true` snapshot is
general evidence that the OS currently reserves interaction for trusted phone
UI, not a per-call transfer-picker acknowledgement. API v3 has no exact
per-request callback for picker accepted, rejected, displayed, selected or
cancelled. Adding such an acknowledgement would be an additive, separately
specified API evolution; the 3.1.0 extension does not add it.

## Session operations

- `enableExternalUi` leases total external-screen ownership and asks the OS to
  resolve the fixed secondary-home component. It never affects phone Home.
- `showShell` starts only the fixed shell component on the exact live monitor.
  The shell is an ordinary secure APK Activity; no surface or input-channel
  handle crosses Binder.
- `enableShortcuts` leases the registered desktop command set when
  `CAP_SHORTCUTS` is present. `onCommand` contains a registered command,
  bounded argument, focused opaque task token and invoking display token; it
  is not a raw input stream. Workspace arguments are 1 through 9, monitor
  arguments are 0 through 2, and all other current commands use zero.
- `applyFrame` requires `CAP_FRAME`, current revisions, every task exactly once,
  contained placements, complete unique z-order and bounded shell regions.
- `applySignedFrame` has the same identity, completion and shell constraints,
  but is usable only with `CAP_SIGNED_PLACEMENT` and admits finite signed task
  geometry. It does not widen `applyFrame`.
- `focusTask` accepts only a current visible/input-enabled task.
- `closeTask` accepts only a current task. Both complete through `onResult`
  after observing the exact native outcome.
- `launcherPage` requires `CAP_APK_LAUNCHER`. `(catalogId=0, offset=0)` attempts
  to create a one-shot OS catalogue for a live display and returns null if no
  page is admitted. Pages contain at most `MAX_LAUNCH_PAGE` entries from at
  most `MAX_LAUNCH_ENTRIES`; entries expose a label, resolved component string
  and catalogue-local index, never an Intent, UID or native handle. Later pages
  must preserve scope and arrive before `expiresAt`.
- `showLauncher` starts only the fixed launcher Activity on the catalogue's
  monitor. `selectLauncher` consumes the catalogue once; an out-of-range index
  cancels it. Reusing an existing phone task requires trusted phone-side
  confirmation.
- `showTransferPicker` requires `CAP_TRANSFER_PICKER` and asynchronously asks
  the OS to open trusted phone-side exact-task selection for the named monitor.
  It provides no exact admission or outcome acknowledgement. Cancellation and
  a stale or removed task change no desktop authority.

`CAP_EXTERNAL_UI`, `CAP_SHELL`, `CAP_APK_LAUNCHER`,
`CAP_TRANSFER_PICKER`, `CAP_SHORTCUTS`, `CAP_FRAME`, and
`CAP_SIGNED_PLACEMENT` must each be checked before using their behavior.

## Scope of the SDK artifact

The Maven coordinate for this documentation source is
`org.wonad:desktop-sdk:3.1.0`. A publication contains the AAR,
sources JAR and a `contract` classifier ZIP holding this complete specification
and the unchanged API-v3 machine baseline. That baseline binds the complete
exported JVM class, field, method, descriptor, generic-signature, exception and
constant ledger as well as the ordered AIDL wire declarations and Kotlin source
API. Passing `sdk_contract.py` proves source equality with that reviewed
baseline; publication verification additionally derives the ledger from the
actual AAR and requires an exact match. Neither check is runtime, signer, pixel,
fault-injection or device qualification. This source document does not identify
or authorize any particular artifact bytes; immutable publication evidence
must supply exact artifact and contract-member hashes and pass all existing
archive, wire, ABI and inventory checks.
