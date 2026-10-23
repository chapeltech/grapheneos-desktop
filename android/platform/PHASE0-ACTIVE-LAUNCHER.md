# Finishing catalogue role and external pointer focus

This is a development correction to the native implementation of the existing
desktop contract. It does not change API v3 / SDK 3.0.1, the trust policy, APKs,
the emulator runtime, or the requirement that ordinary phone focus is permitted.

## Reproduction and cause

The retained quiet hotplug run on image
`sha256:bd7e1b6e500e043f1dc8883992b5c5da2d91437a567c81d98e523b81f246b739`
completed ten populated redocks but failed when reopening the external launcher
after cancelling its trusted phone-window import confirmation. Its private raw
evidence is retained at
`/u/elric/.local/state/wonad/phase0-test-work-20261019-1/quiet-desktop-1`.

`phone-import-cancelled-windows.txt` shows the old `LauncherActivity` finishing
while its window remains visible, drawn and shown. The cancellation completes
and ordinary phone Home regains focus. A subsequent real external pointer event
is received by the external display's pointer dispatcher, targeting the old
launcher's stock `ActivityRecordInputSink`. The following keyboard chord goes to
phone Home. The old launcher close transition completes only after its five-second
readiness timeout. This is distinct from the older second-redock click failure
which lacks an initiating kernel event and remains separately recorded.

`WonadNativeBridge.registerPointer` previously ignored the fresh pointer event
because `launcherWindow(plane)` still returned that finishing catalogue. Its
component, permission, user, UID, generation, catalogue, visibility, drawing and
secure-window checks did not exclude a finishing Activity.

## Correction and retained invariants

The exact-role selector now also requires `!activity.finishing`. Closing remnants
no longer own active catalogue interaction. A genuine new catalogue still wins
regardless of the order of its predecessor in the window list.

The change does not remove Android input sinks, move a task using an APK-supplied
identifier, disable phone input, or automatically steal focus from phone Home.
The existing fresh native pointer-down, exact-home geometry, lease identity,
protected-phone-UI and blocked-environment checks still govern background focus.
All existing role authentication checks remain present.

## Evidence and limits

The compiled selector regression retains the original image's source as a
negative control, which fails specifically at `closing_launcher_is_not_active`.
The corrected selector passes 15 deterministic checks, including replacement
ordering and every original identity/visibility/secure-window rejection. The
existing compiled launcher-close focus suite also passes. These are selector
tests, not live WMS/input qualification.

The original and corrected bridges compile against the pinned real framework.
The original reproduces all 71 retained bridge classes byte-for-byte, including
the Kotlin repackaging stage. Services transformation preserves all 11,208
unrelated pre-DEX class/resource entries. Packaging retains the hotplug-renewal
SystemUI and checks AVB and all seven actual embedded OS roles; only services
changes relative to that parent.

The exact new image
`sha256:01ca6e31c6c0405d5c0c3a2d1b88e3426a06e11e2fa75e264ba83c231d0ef2ec`
passes the [quiet runtime repetition](../out/phase0-active-launcher-20261019-1/runtime-audit.json):
ten populated redocks, the original cancel/click/keyboard-reopen sequence and a
subsequent explicitly confirmed transfer of the same Contacts Task. There is no
input repair, retry or added transition-delay workaround. The 20 populated
checkpoints retain one Wonad instance/PID/generation and the original two Task
objects. This is a bounded pass, not proof of every transition schedule.

The separately derived ordinary API-test image passes all 16 operations, four
callbacks, capability mask 2024 and three facades. All seven live OS files match
the product image; boot identity and protected-process PIDs are unchanged across
the test, and the released external X11 frame is actually black. Broader Phase 0
handoff qualification and independent review are not inferred from these runs.

Producer tools:

- `android/tools/compile_phase0_ui_renewal.py`
- `android/tools/package_phase0_active_launcher_os.py`
- `android/tools/build_phase0_active_launcher_image.py`

Raw failed attempts, immutable parent proofs and private userdata must retain
their original identities; do not relabel them as passing new-image evidence.
