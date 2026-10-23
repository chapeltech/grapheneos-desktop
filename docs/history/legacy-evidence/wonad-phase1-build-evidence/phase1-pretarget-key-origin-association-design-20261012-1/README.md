# Phase 1 pre-target key-origin and display-association review

Date: 2026-10-12

Status: external, read-only source review and design only. This is not an
implementation, Android build result, runtime result, or Phase 1 qualification.
It supersedes the earlier *Reader-only* inference that an ordinary hardware
keyboard necessarily remains `INVALID_DISPLAY`. It does not rewrite any
historical review or RED evidence.

## Bounded conclusion

The pinned Android input stack already resolves most unassociated hardware
keys to InputDispatcher's current focused display before
`interceptKeyBeforeQueueing`, but it does not carry enough authenticated origin
state to prove that the key belongs to the exact current claimed external
window/display incarnation. Injected keys take a different path and preserve
the incoming display ID; they must never inherit hardware authority.

Existing runtime port/descriptor-to-display association APIs are not suitable
as a Wonad authority mechanism. They globally change InputReader routing and
device configuration, are asynchronous, do not bind an owner/user/claim or
display/device incarnation, and can split a physical DOWN/UP pair across an
association change. They should not be used to establish Phase 1 input origin.

The smallest source-backed design is therefore a private, immutable
queue-origin proof captured under InputDispatcher's lock, combined with a
lock-free token-to-exact-claim registry published by WMS. The initial physical
DOWN must establish the lineage retained through repeat/UP/cancel/reset. A
focused display number alone is insufficient.

## Exact reviewed sources

Pinned custom-7 root:
`/u/elric/tree/wonad-grapheneos-2026100600-phase1-custom-7`

| Path relative to the pinned root | SHA-256 |
| --- | --- |
| `frameworks/native/services/inputflinger/dispatcher/InputDispatcher.cpp` | `4598e3a96e0196a5965be2a4232736ba7e14616c8435b201ab6d394e44b762c9` |
| `frameworks/native/services/inputflinger/dispatcher/InputDispatcher.h` | `713ca2351b28ebde8829edada02bea18c4923614f353bd7ca277eff69f4994d6` |
| `frameworks/native/services/inputflinger/dispatcher/FocusResolver.cpp` | `ed6a861b85cb67e5cc57b31455667f16b77f8c3c264a4074fa8645b3790006c3` |
| `frameworks/base/services/core/java/com/android/server/input/InputManagerService.java` | `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1` |
| `frameworks/base/services/core/jni/com_android_server_input_InputManagerService.cpp` | `0a71ebf0fb6697a1f21a6abe0e14e53d4b961e40a4baace0b8dedb0d5b8c08c5` |
| `frameworks/native/services/inputflinger/reader/InputReader.cpp` | `3a5acd8dbbd4d880a27eb84d9de68cbcceb81a91593749340a1800be7856eb5d` |
| `frameworks/native/services/inputflinger/reader/InputDevice.cpp` | `5a27592c180326513ef9aa3260a8f126ada0c5b3cfe24b942bf63c59ae339cea` |
| `frameworks/native/services/inputflinger/reader/mapper/KeyboardInputMapper.cpp` | `0a8bc5d7d66b02d4faac11f9c8252e6bb059f7ad2f4cbbae80865d32a810f303` |
| `frameworks/native/services/inputflinger/include/InputReaderBase.h` | `aeab719a00de6400b3c6c9f19d6d78c20da88b9328cb6dab7aa3955aa9323846` |
| `frameworks/native/services/inputflinger/InputReaderBase.cpp` | `f265b635c3e2e031a001966ed4251ca768ae615285ecad125174f4cf2e879d09` |
| `frameworks/native/services/inputflinger/reader/include/InputDevice.h` | `5261231edbe36deb1b338ed66635898d64ea76140244af8d0c2c62f1ab533d7a` |
| `frameworks/native/services/inputflinger/reader/EventHub.cpp` | `38f5775af51d5bbe09d7c87778a510a35f52120e46f1b000202aa16052659d97` |
| `frameworks/native/include/input/InputDevice.h` | `264e7e5dd111ba1b2d887ec4ade15aedf864776501e0c6469ca65bb4f9892cbe` |
| `frameworks/native/include/input/DisplayViewport.h` | `d18c207e4ea63a775e3b7b903dfdea7b3a0b47741dc3a5662294ee01bd7575c6` |
| `frameworks/base/core/java/android/view/InputDevice.java` | `4dc4b81ff00c8c8868a6822f4f8853ca7f1b80c3fdb22704b53be1382aa83957` |
| `frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java` | `25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898` |
| `frameworks/base/services/core/java/com/android/server/wm/WindowManagerService.java` | `c2eb228520a585d86aa4097230f5c88700d32c08cbc8f2cf4da93b3787d6342c` |

Current workspace claim/containment inputs reviewed without modification:

| Path | SHA-256 |
| --- | --- |
| `android/input-integration/src/com/android/server/wm/WonadUiBridge.kt` | `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4` |
| `android/input-integration/src/org/wonad/server/input/WonadInputBridge.kt` | `b512112fe58157e8e1a18baa3dbf0c0c338f073ea4d901c63d9949aaa11e60ff` |

## Corrected hardware and injection inventory

### Hardware `notifyKey`

`InputDispatcher.cpp:886-897` defines
`calculateIntendedDisplayIdLocked`:

- SLEEP, POWER, and WAKEUP retain the reader-provided display ID.
- For other keys whose reader display is `INVALID`, the intended display is
  `mFocusedDisplayId`.
- A reader-specified display is retained.

`InputDispatcher.cpp:4576-4628` shows the complete queue-policy boundary.
`notifyKey` acquires `mLock`, computes that intended display, releases the lock,
initializes the Java `KeyEvent` with the intended display, and then invokes
`interceptKeyBeforeQueueing`. Therefore an ordinary unassociated USB/Bluetooth
keyboard is normally visible to queue policy with the then-focused display,
not necessarily `INVALID_DISPLAY`.

That resolution still does **not** prove claimed authority. The current path
does not capture or pass the focused input token, a focus epoch, an exact
display/claim incarnation, or a stable physical-device incarnation alongside
the queue callback. A numeric focused display can change or be reused, and a
different window can acquire focus between observations. Thus the design still
needs the exact focused token/native display incarnation/device incarnation and
initial-DOWN lineage described below.

Later, `InputDispatcher.cpp:6877-6892` calls
`interceptKeyBeforeDispatching` with the resolved display and focused-window
token outside `mLock`. That later target evidence is useful, but it is after
the queue-stage stock effects that this design must classify or defer.

`InputDispatcher.cpp:5900-5954` cancels unreleased display-unspecified events
when the focused display changes. Display-specified events are explicitly not
covered by that cancellation. This stock behavior does not replace exact Wonad
pair lineage across focus/claim/device transitions.

### Injection

`InputDispatcher.cpp:4946-5022` is a distinct path. It adds
`POLICY_FLAG_INJECTED | POLICY_FLAG_TRUSTED`; normally replaces the device ID
with `VIRTUAL_KEYBOARD_ID` (filtered events are the documented exception);
copies the incoming key's display ID unchanged; and, for unfiltered events,
invokes queue policy with that event. It does **not** run
`calculateIntendedDisplayIdLocked`.

Consequently the proposed proof must label injection explicitly and must never
turn an injected, filtered, or accessibility-synthesized event into physical
claimed-device authority merely because it carries an external display ID.

## Why current association APIs are not authority

`InputManagerService.java:1845-1954` exposes runtime association by input port,
display port, device descriptor, or display unique ID. The Java map mutation
occurs under `mAssociationsLock`; the native notification happens after that
lock is released. `InputManagerService.java:3122-3153` supplies copies of the
whole maps to native.

The source-backed problems are:

1. The keys are a port/location or descriptor, not an authenticated current
   device incarnation, current claim owner, user, lease, or display
   incarnation.
2. Refresh is asynchronous. Native requests a `DISPLAY_INFO` refresh;
   InputReader later obtains configuration and reconfigures devices.
3. `KeyboardInputMapper` reads the current viewport separately for each event.
   Its reconfigure path can replace the viewport while retaining key-down
   state. A DOWN before association refresh and matching UP after refresh can
   therefore have different display IDs.
4. Association affects global dispatch configuration, enabled state,
   `canDispatchToDisplay`, and input-device generation. It is routing mutation,
   not a passive origin observation.
5. External-device descriptors are not a persistent active-instance identity.
   EventHub only disambiguates concurrently connected descriptor collisions;
   reconnect/order can change that result. Java `InputDevice` documentation
   likewise warns against using descriptor as a runtime logical-instance ID.
6. A display unique ID is not an adequate claim incarnation. Explicit virtual
   display unique IDs can be reused, and the viewport lookup logs duplicate
   unique IDs rather than treating them as authority failure.
7. Removal/restoration is caller-owned and can outlive unplug, process failure,
   claim retirement, or display replacement.
8. Calling these APIs from a WMS claim path would add an undesirable WMS-global
   to InputReader/configuration edge and still would not provide an atomic
   per-key proof.

InputReader's own tests/documentation also treat dynamic device-to-display
association as unsupported for the use required here. Therefore the Phase 1
design must not add/remove these global associations to classify a key.

## Minimal private queue-origin proof

This is an internal design, not a proposed public APK or SDK API.

For a hardware key, InputReader/InputDispatcher should carry an immutable
`QueueOriginProof` containing at least:

- event ID, event time, DOWN time, action, scan/key code, and source;
- a new private 64-bit device-incarnation serial allocated once for the native
  `InputDevice` object and retained on every event from that object;
- device ID plus current generation, identifier, external/virtual bits and
  sources for diagnostic consistency, but not as the sole authority;
- raw reader display ID and the intended display computed under
  InputDispatcher `mLock`;
- focused input token for that intended display captured under the same lock;
- a monotonic focus epoch incremented for focused-display and focused-window
  changes; and
- an explicit origin kind: hardware, injected, filtered, or accessibility.

Why every identity is needed:

- `deviceId` can be reused after removal; generation can also change for a
  configuration event. The private incarnation prevents a hotplug replacement
  from completing an old pair.
- intended display alone is a transient numeric selector, not proof of the
  window or current Wonad claim.
- token alone needs the display/focus epoch to reject stale or transient focus.
- display unique ID alone does not prove the native display/claim incarnation.
- current workspace `ShortcutClaim` already binds display, user, generation,
  incarnation, and owner. Authority must compare the exact immutable claim
  object, not only its fields or numeric display ID.
- the initial physical DOWN must own repeats and the terminal UP/cancel. A
  later focus/claim change can force drain-only behavior but cannot reclassify
  the existing pair or grant a new stock command.

InputDispatcher currently caches `InputDeviceInfo` under its lock when it
receives `notifyInputDevicesChanged`. InputReader can, however, process an
event after configuration refresh before the later device-change notification
is appended/flushed. Therefore the authoritative incarnation must travel with
the event from the actual native device object; it must not be reconstructed
only from the dispatcher's possibly lagging device-info cache.

Injected input gets an explicit injected proof with no physical incarnation
and can never establish claimed-device authority.

## Exact WMS claim registry

WMS should publish a volatile immutable map from every focused-capable input
token on an exact currently claimed `DisplayContent` to the exact current
`ShortcutClaim` object. It is private system-server state, not a Binder or APK
surface.

Required rules:

- Publish/remove under the WMS global lock as input windows and claims change;
  queue-policy readers perform only a lock-free snapshot lookup.
- Publish the claim's blocked/departure barrier before unpublishing tokens.
- A replacement display or claim gets a new immutable claim object even if the
  numeric display ID or display unique ID is reused.
- Authority requires token identity, intended display, focus epoch, current
  exact claim object, active claim state, physical device incarnation, and the
  initial-DOWN ledger entry to agree.
- Token absent while a claim/barrier exists is transitional and fails closed
  for non-safety global UI. Token absent on a genuinely unclaimed phone/display
  keeps stock behavior.
- Internal-display keys remain phone stock unless a separately reviewed exact
  rule says otherwise. External keys proven against a claimed token enter the
  claimed domain. No top-focus or monitor topology guess may substitute for
  the token/claim join.
- Device removal/reset retires every ledger entry for that exact device
  incarnation. Display/claim retirement moves existing pairs to drain-only.
- Multiple claimed monitors remain independent by exact claim object and
  token; a stale pair on one cannot affect another.

## Queue containment and bounded fallback

Preferred implementation:

1. Extend the private native-to-Java queue callback with the proof above.
2. Classify the exact initial DOWN before KGC/PWM can run non-safety global
   effects.
3. Carry a private policy marker to later policy seams; do not expose a public
   handle or widen the SDK.
4. For exact claimed external origin, suppress every direct healthy stock UI
   route required by the simplified Phase 1 policy, including Recents/all
   apps/Alt-Tab, screenshot/SYSRQ and corresponding before/after/unhandled/
   fallback routes. Preserve pair draining and the separately documented fixed
   Wonad commands.
5. Phone/unclaimed input follows the byte-for-byte stock path. Injection never
   receives physical claimed authority.

If queue origin cannot yet be proved, a larger fallback is to defer only an
explicitly enumerated set of non-safety stock effects until the existing
target-resolved callback supplies the exact focused token/display. Queue policy
would record one bounded immutable effect obligation without performing it;
the target seam would either execute the stock effect for proven phone/
unclaimed origin or consume it for claimed/transitional origin.

That fallback must not call PWM twice. Its queue method mixes pass-to-user,
wake/state decisions, gesture detection, haptics and immediate/posted effects.
Every deferred branch would need a source-specific split, a fixed per-device
cap, terminal pair parity, rejection/reset cleanup, and no helper/global lock.
It is therefore a contingency design, not a current acceptance claim.

## Safety and stock-effect boundary

This review does not invent a universal definition of a safety key. The exact
Phase 1 effect inventory must remain explicit. Queue policy contains boot/
interactive/wake decisions; global-key handling; single/multi-key gesture
handling; BACK/focus behavior; volume/call/media/ENDCALL; TV_POWER/POWER;
system-navigation, sleep and wake; mic mute; assist/voice assist; PiP WINDOW;
stylus/status-bar actions; macro/demo paths; haptics; and possible
`moveDisplayToTopIfAllowed` behavior.

The simplified successor may retain only the already reviewed hardware-safety
and Secure Paste exceptions. In particular, the actual phone's Power and
Volume behavior must remain stock. Whether an external keyboard's Power or
Volume keys are exceptions is a policy/runtime decision that needs an explicit
case; it cannot be inferred from a generic key class. Cross-device KCM chord
mixing for retained exceptions remains an open Phase 1 review/runtime
obligation and is not solved by ordinary claimed-key containment.

## Lock-order requirement

The viable ordering is deliberately one-way:

1. InputReader creates/carries the device incarnation while under its own
   lock, then flushes to InputDispatcher after releasing the reader lock.
2. InputDispatcher captures intended display, focus token and focus epoch under
   `mLock`, then releases `mLock` before invoking Java policy.
3. Java policy performs a lock-free immutable registry lookup. Its small
   physical-pair ledger calls no WMS, IMS, InputReader, Binder or Settings code
   while holding the ledger lock.
4. WMS global-lock code only publishes immutable registry/barrier snapshots and
   posts any cleanup to an existing handler after releasing WMS global.

There must be no WMS-global/helper-to-InputReader association mutation and no
InputDispatcher-lock-to-WMS synchronous call. This design also avoids the
previously proven helper-to-KGC/PWM-to-WMS inverse by performing only bounded
classification/ledger mutation under its local lock.

## Required hostile tests before implementation can qualify

- Hardware `INVALID_DISPLAY` initial DOWN resolves to the exact current
  focused display/token under one InputDispatcher lock epoch.
- Hardware with an explicit associated display retains it, but still cannot
  authorize without the exact token/claim/incarnation join.
- Injected, filtered and accessibility-generated keys with a claimed display
  never gain hardware authority.
- Focus display/window changes between queue and target make the existing pair
  drain-only; they cannot grant stock UI.
- Display ID/unique-ID reuse with a new native display/claim incarnation is
  rejected.
- Device ID reuse after unplug with a new private incarnation cannot complete
  the old UP.
- Association refresh between DOWN and UP cannot reclassify the pair; no
  association API is called by Wonad.
- Two claimed monitors and two physical keyboards keep independent exact
  lineages; no token/claim cross-use.
- Missing token during claim publication/departure fails closed for non-safety
  stock UI without suppressing unrelated phone/unclaimed input.
- Initial DOWN, repeats, UP, cancel, device reset and saturation retain exact
  pair parity and bounded state.
- Every retained safety/Secure Paste exception has a separately named
  cross-device-chord control; ordinary claimed input does not silently imply
  those exceptions are isolated.
- Lock instrumentation proves no callback/Binder/Settings/WMS/InputReader call
  occurs while holding the queue ledger lock and no WMS-global-to-InputReader
  association edge is introduced.

## Limitations

No repository, OS source, stage, packet, SDK, image, guest or runtime evidence
was changed or executed for this review. There is no compiled implementation,
no hardware/Bluetooth runtime result, and no claim that the current partial
post-target prototype satisfies this pre-target origin requirement. The exact
stock-effect policy and retained safety exceptions still require source-bound
implementation plus compiled and real-device/emulator qualification.
