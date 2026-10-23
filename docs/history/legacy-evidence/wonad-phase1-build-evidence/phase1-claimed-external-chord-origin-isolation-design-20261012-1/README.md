# Claimed-external chord-origin isolation design (source review only)

Date: 2026-10-12

Status: external design evidence only. This directory contains no Android source
change, compiled object, image, or runtime result. It does not qualify Phase 1.

## Reviewed bytes and factual defect

Pinned custom-7 source:

- `frameworks/base/services/core/java/com/android/server/input/KeyGestureController.java`
  SHA-256 `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`
- `frameworks/base/services/core/java/com/android/server/input/KeyCombinationManager.java`
  SHA-256 `c0fc0486e537637ab9e1006eba597b1840692e7f6eb24c8c5ab9f466b4d46044`
- `frameworks/base/services/core/java/com/android/server/input/InputManagerService.java`
  SHA-256 `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1`
- `frameworks/base/services/core/java/com/android/server/policy/PhoneWindowManager.java`
  SHA-256 `25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`
- reviewed current private `android/input-integration/src/com/android/server/wm/WonadUiBridge.kt`
  SHA-256 `8d227e84eef912d1016698e018ca37642cff8ec0150a380eb25dbf7e8dc21da4`

`KeyCombinationManager` stores down times, active rules, and one triggered rule
globally by keycode. It records neither device nor display. An external claimed
Volume-Down and a phone Power event within 150 ms can therefore trigger one
rule; either origin's terminal event can cancel it. `handleMultiKeyGesture`
then deliberately replaces provenance with virtual-keyboard/default-display.
This is stock behavior, but it means ordinary raw-input isolation is not proof
that a claimed external key cannot participate in a phone/global safety chord.

## Required invariant

Only an event authenticated against an already-published exact Wonad UI-claim
incarnation is separated from the stock chord domain. Phone and every unclaimed
event remain in the single original stock domain, including their current
cross-device behavior. Actual phone Power/Volume processing in
`PhoneWindowManager.interceptKeyBeforeQueueing` is unchanged.

Events in different domains must never start, complete, cancel, delay, or mark
consumed one another's chord. A claimed event's initial-DOWN domain remains its
domain through repeats, cancellation, and UP even if the claim is blocked,
retired, replaced, the display is recycled, or focus moves.

## Narrow implementation shape

1. Publish a private, immutable chord-origin token alongside the existing
   volatile exact `ShortcutClaimState`. Reading it must be a lock-free snapshot:
   no WMS-global acquisition, package/settings lookup, Binder call, or authority
   admission. A retained expired/dead exact state is still a claimed origin;
   expiry must not make an in-flight key fall back into the phone domain.
2. Before taking `KeyCombinationManager.mLock`, resolve one domain for the
   initial event:
   - `STOCK` for phone and all events with no exact published claim;
   - `CLAIM(claim-object-identity, displayId, deviceId)` for an exact claimed
     external origin.
   Object identity, not generation/display numbers alone, prevents recycled
   claims from joining. Including device ID prevents two physical external
   devices from fabricating a single chord.
3. On first DOWN, retain the chosen domain under physical lineage
   `(deviceId, keyCode, downTime)`. Repeats, UP, and cancellation use that
   retained domain rather than re-resolving mutable claim/focus state.
   `FLAG_FALLBACK` events remain excluded from chord recognition exactly as
   today and may not create or migrate a chord lineage.
4. Move the existing down-time/active-rule/triggered-rule state into a bounded
   per-domain record. Keep one permanently available stock record; a claimed
   capacity failure must never merge into or disable the stock record. It must
   select an isolated no-mix/fail-closed claimed record and be observable.
   Bounds and device-removal/all-released cleanup are mandatory; stale claimed
   records cannot consume future stock events.
5. `isKeyConsumed` and `getKeyInterceptTimeout` must use the retained lineage
   domain. An event-time re-resolution is incorrect: claim retirement between
   queueing and dispatch otherwise restores cross-domain cancellation or leaves
   an orphaned consumed half-pair.
6. Rule execute/cancel remains posted as it is now. Domain resolution and exact
   claim access occur outside `mLock`; callbacks under `mLock` may not call
   Wonad, WMS, settings, Binder, or package state. No public API/AIDL/SDK change
   is required.

This design intentionally does **not** remove the reviewed hardware-safety
exception. A Power/Volume chord produced wholly inside one claimed physical
domain can still perform the existing action, and current KGC still targets
default display for it. That policy is separate from preventing a claimed key
and phone/unclaimed key from composing one chord.

## Mandatory controls before integration

- phone Power + phone Volume triggers and cancels exactly as current stock;
- phone device A + other unclaimed device B retains current stock composition;
- claimed Volume + phone Power does not trigger, delay, consume, or cancel the
  phone chord; reverse order has the same result;
- same exact claimed device Power + Volume retains the documented safety action;
- two claimed devices, two claim incarnations, and two claimed displays do not
  compose;
- retirement/replacement/focus migration between DOWN and UP drains the old
  lineage only;
- concurrent stock and claimed chords complete/cancel independently;
- missing UP, device removal, all-keys-released census, saturation, and display
  recycling cannot strand a consumed key or affect the stock record;
- fallback/injected controls prove no hidden reclassification. Injection can be
  test evidence only when its explicit display/device provenance is bound; it is
  not proof of physical-device association;
- raw phone Power and Volume still reach the unchanged PWM queueing path.

## Honest limits / open runtime evidence

The source review does not establish what display ID every real USB/Bluetooth
keyboard receives before queueing. If a physical claimed keyboard arrives with
`INVALID_DISPLAY` or default display, an exact claim token cannot be inferred
from mutable top focus. Such a device must not be guessed into the claimed
domain. Product integration therefore needs a source-matched device-to-display
association proof and real simultaneous phone/external chord tests. The design
does not claim those tests, Android compilation, or runtime qualification.
