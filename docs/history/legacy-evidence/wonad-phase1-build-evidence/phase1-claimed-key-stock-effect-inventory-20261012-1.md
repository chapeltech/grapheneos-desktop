# Claimed-key stock effect inventory

Date: 2026-10-12

This is a bounded read-only source review, not a patch, build, runtime result, or
qualification claim.

## Source identities

The reviewed custom-7 source files are:

- `KeyGestureController.java` `3acaa08d5a39200bbcd521f760339c4d531936656899c195b9b9fa9b28aa66c5`
- `KeyCombinationManager.java` `c0fc0486e537637ab9e1006eba597b1840692e7f6eb24c8c5ab9f466b4d46044`
- `InputGestureManager.java` `bd99d2ed7e12ace76b72e93d5ec28d90dde25b966b95f98569344a5cadf18faa`
- `InputManagerService.java` `df0e4cc78508383cd60fd2cd534ba450a0df2071b211ee21115fa71f35470dc1`
- `PhoneWindowManager.java` `25be0cd9384ef463af854067e4904701041ece23ef0e9b9f8cc348503e6e1898`
- `KeyboardInputMapper.cpp` `0a8bc5d7d66b02d4faac11f9c8252e6bb059f7ad2f4cbbae80865d32a810f303`
- framework resource `config.xml` `d9121e6c004d52b9f4e21d2e051f12efd7ab46f37b8c288e0314392a6d16b53f`

## Explicit retained exceptions

The current design decision retains multi-key hardware safety and Secure Paste
ahead of healthy-claim stock suppression.

Multi-key rules can take screenshots, invoke the accessibility shortcut, mute
the ringer or open global actions, and (on Leanback) request a TV bug report.
They execute before claim handling. `handleMultiKeyGesture` reports virtual
keyboard/default display, so the screenshot request targets display 0 rather
than the claimed display. The key-combination ledger is global by keycode and
can combine/cancel keys from different devices; this remains an explicit open
Phase-1 runtime/review obligation, not ordinary-input isolation evidence.

Secure Paste calls stock window policy, then fail-black containment, then grants
the exact focused app. It is a deliberate app-event exception, not stock global
UI.

## Post-target routes that a healthy claim can suppress exactly

After InputDispatcher has supplied the event display, the source currently has
these stock routes before or after app capture:

- direct RECENT_APPS, APP_SWITCH and ALL_APPS;
- direct SCREENSHOT (the event display is passed to ScreenshotHelper), LOCK,
  FULLSCREEN, DND, ACCESSIBILITY and contextual-input/search keys;
- HOME and any configured PWM global key through the before-capture callback;
- non-capturable system Meta shortcuts: HOME, multi-window/desktop/split/move
  display/freeform/desk/quit-task and contextual-input operations;
- capturable and custom shortcuts: screenshot, Recents, assistant, settings,
  notifications/quick settings, search, app/bookmark launch, accessibility,
  language/layout, shortcut helper and related global actions;
- stateful Meta-to-All-Apps, Meta+Alt Caps action, and Alt+Tab Recents;
- unhandled Ctrl+Space, accessibility, SYSRQ screenshot, and Escape close-all-
  dialogs;
- the final Meta fallback path, which otherwise consumes an ordinary Meta event
  or asks InputManagerService to synthesize a fallback event.

A correct healthy-claim path must not merely add key cases. It must prevent new
actions in all three stock stages and the final Meta fallback while preserving
ordinary app dispatch and non-UI fallback delivery. Direct reserved system/UI
keys are consumed with exact DOWN/repeat/UP drainage. Ordinary Meta, Alt and
Escape remain app events unless they are a fixed Wonad command. The unhandled
pass suppresses stock UI but can allow InputManagerService to generate a
non-stock fallback, whose retained claim lineage is checked again on re-entry.

The stage's existing consumed-pair ledger still needs terminal service. A stock
DOWN admitted before a claim and a claimed DOWN retained after retirement must
not exchange ownership, clear one another's singleton state, or leak an UP.
Initial-DOWN origin is the recommended pair authority unless a separate exact
retroactive-cancellation policy is explicitly adopted.

## Queue-time effects not closed by a dispatch-only change

InputManagerService always calls PWM queueing after KeyCombinationManager and
before target dispatch. PWM can already launch assistant/voice assistant, show
PiP controls, handle system navigation, send stylus keys to StatusBar, deliver
configured global keys, and perform Power/sleep/wake/volume/ringer/call/media/
microphone/end-call actions. These are not blocked by any later KGC guard.

This cannot be solved safely by reading mutable top focus at queue time. A
physical keyboard's `KeyboardInputMapper::getDisplayId()` is its associated
viewport display or `INVALID_DISPLAY`; ordinary unassociated USB/Bluetooth
keyboards emit `NotifyKeyArgs` with that value. InputDispatcher target
resolution occurs later. Therefore queue-time UI actions must be either:

1. explicitly documented as additional hardware-policy exceptions;
2. supplied an authenticated pre-reader device-to-claimed-display association;
   or
3. deferred to a post-target seam while preserving all phone/unclaimed stock
   behavior.

Guessing from top focus, treating every external device as claimed, or using a
generic numeric external display would violate phone/unclaimed isolation and
the existing authority model.

## Minimum controls for the simplified successor

- every listed post-target stock UI route is absent for a healthy exact claim;
- Power/Volume multi-key safety and Secure Paste retain their reviewed order;
- direct screenshot and unhandled SYSRQ are negative controls distinct from the
  retained default-display screenshot chord;
- claimed APP_SWITCH/RECENT_APPS/ALL_APPS and exact Alt+Tab Tab pairs drain;
- ordinary Meta/Alt/Escape DOWN and UP remain balanced app events;
- claim retirement/focus migration cannot make late UP, unhandled, or fallback
  enter stock policy;
- claimed saturation is isolated per origin/device and cannot suppress phone or
  unclaimed HOME, Recents, typing, or modifiers;
- phone/unclaimed stock behavior remains byte-for-byte at each stage;
- runtime claims separately disclose the unresolved queue-time and cross-device
  hardware-chord boundaries.
