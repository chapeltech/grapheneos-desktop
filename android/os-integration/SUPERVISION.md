# OS-owned desktop APK lifecycle

The desktop wire API remains v3. Window selection, workspaces, layouts and
keyboard policy remain in the separately signed, ordinary Wonad APK.

SystemUI supervises the client using Android's normal bound-service lifecycle:

- Component: `org.wonad.desktop/.DesktopService`.
- Bind action: `org.wonad.desktop.SUPERVISE`.
- Required caller permission: `android.permission.STATUS_BAR_SERVICE`.
- The APK returns a plain non-null Binder. It carries no window-management RPCs,
  permissions, surfaces or authority. This component/action/caller restriction
  is the lifecycle compatibility contract; preserve it in successor APKs.
- The APK is not granted that privileged permission. Its existing API3 broker
  session must still independently authenticate and satisfy native admission.

Binding requires the foreground user to be credential-unlocked, the keyguard
to be clear, the existing per-user OS enable setting to be on, an eligible
external display, and the fixed package with the configured signing identity.
The service must be enabled, exported and protected by the exact caller
permission above. Android's stopped and suspended flags are checked. No consent
setting or package stopped flag is written by the supervisor.

First installation still requires opening Wonad and enabling it in the protected
OS settings UI. Thereafter no Start/Retry click is needed. The emulator launcher
does not reopen the phone control panel on supervised-image boots. Phone HOME,
navigation, apps and input behavior are not replaced by this lifecycle feature.

The OS unbinds and stops the service when disabled, locked, switched away from
its user, or disconnected from the last eligible monitor. Process/binding death
retries after 1, 2, 4, 8, 16 and then at most 30 seconds; 60 seconds of healthy
binding resets the crash history. A pending binding times out after 15 seconds.
Package identity/version changes reset the attempt. Stops are revalidated
against the exact user, UID, version and update time before execution.

Binding readiness is not keyboard-focus authority. A replacement service must
still open a fresh desktop session and satisfy native focus/protected-phone
guards; the lifecycle Binder cannot override the phone's current focus.
The [shipping-image recovery check](../out/phase0-supervision-recovery-20261020-1/README.md)
preserves a failed no-click shortcut after otherwise successful populated process
recovery. Android has focused phone Home while the emulator's host X11 window
remains focused. One explicit external content click restores keyboard operation
in the separately tested re-entry case. This is a current workaround, not an
automatic-focus-restoration guarantee or a waiver of the retained failure.

The native cause is explicit in `WonadUiBridge.reconcileNativeHomeFocus`: parking
lowers only the exact claimed display and withdraws its authenticated HOME's
focusability; recovery passively restores owned bits without raising a display
or selecting an app. Android's stock global-focus scan can therefore choose the
ordinary phone. The [compiled parked-HOME tests](../tests/test_native_parked_home_focus_compiled.py)
execute that helper and the pinned stock scan, including the requirement that
recovery does not raise or select HOME/phone/app. Automatic focus restoration
would be a separate behavioral change requiring explicit phone-intent and
held-key/failure qualification, not a change to the SUPERVISE Binder ABI.

OS **Disable** is the persistent off switch. While Wonad is the selected external
HOME, Android can relaunch that HOME after Force stop and clear the stopped flag;
the supervisor then sees an eligible package again. When no Wonad HOME is claimed,
a stopped package remains stopped until explicitly opened. Disabling and then
force-stopping is covered by the emulator tests.

Use `android/emulator/test-supervision.py` only with its explicitly disposable
guest names. It exercises consent, crash recovery, one/two monitor topology,
lock/unlock, Disable, stopped-package behavior and an orderly Android reboot.
The test taps the real OS settings UI; it never grants permissions or writes the
enable setting directly. Guest-root access is used only to kill the test APK.

Reboot tests use `svc power reboot`, Android's normal shutdown path. A hard
`adb reboot` immediately after clearing Force stop can lose Android's asynchronous
package-restriction write; it is not equivalent to an orderly phone reboot.

The emulator also needs `emulator-multidisplay-startup-order.patch`: its upstream
listener started before its monitor table was initialized. The patch moves the
existing thread start after initialization, preserving Java's publication edge.
It does not change any physical-phone OS interface or the retained front-buffer
flicker fix.
