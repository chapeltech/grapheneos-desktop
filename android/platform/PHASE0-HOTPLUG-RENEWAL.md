# Phase 0: guarded native lease renewal

This is a private OS implementation correction, not a new SDK/API version.
It does not qualify Pixel 10 hardware or complete Phase 0 by itself. The default
user image must not change merely because compilation or packaging succeeds.

## Observed failure

On the retained keyboard-recovery image, two parallel populated-redock runs
captured the initiating SystemUI exception, not just its aftermath:
`Native shortcuts declined` in `Session.renewShortcuts`, followed by reason-5
revocation of the whole native session. The other external monitor was still
attached. Contacts retained its actual Task identity but returned to the phone.

Heartbeat renews UI and shortcut leases before reconciliation. Physical removal
can retire the exact native UI/input claim between those calls. Rejecting a
shortcut renewal for that departed attachment is correct; treating it as a
failure of every remaining monitor is not.

The four original runs are retained separately in the
[evidence directory](../out/phase0-hotplug-renewal-20261019-1/README.md).
They are all failed full-suite attempts: another run missed a physical click;
one completed ten populated redocks but failed a later launcher invocation.
Neither is counted as a successful full-suite control or explained by this fix.

## Boundaries of the correction

`NativeDesktopController.requireLeaseRenewal` keeps accepted calls on their
existing fast path. After a declined private WM call it reauthenticates the
exact owner UID/package/signer and reads fresh native state for that display.
A changed native attachment token, including an attachment no longer admitted
by WM, uses the existing stale-observation reconciliation path. Native state
reports zero for absent/ineligible displays; it is not a new grant of authority.
Global consent/lock/user loss is still enforced by native leases and the ensuing
authority reconciliation. A rejected call never authorizes a replacement display.

Same-attachment declines, malformed native observations, authentication failures,
transport exceptions and JNI/linkage errors remain genuine failures. The broker
attempts every independent sibling renewal, but an earlier stale attachment
cannot hide a later genuine error in the cleanup aggregator. Fatal process
errors are not swallowed. Focus, UI and shortcut renewals use the same rule.

No public Binder transaction, capability, numeric assignment, SDK artifact,
client package/signer, lease duration, callback deadline, workspace policy or
phone-import consent rule changes. No automatic phone-window re-import or input
repair is added.

## Source and build binding

- Original controller SHA-256:
  `67e6e7c96eefb9d33db54494b571a5d037a3efd49b7dc80d562637cfb98e16ca`.
- Corrected controller SHA-256:
  `b5e2ce07023583dce4c2c0cb07a226d6581b481b62dff13ce58300b65e75bd89`.
- Corrected SystemUI SHA-256:
  `1d198f42756fa84b77115dcd7dfd1b5f3368ca2b3fa29a12a4a02d8ff2bff440`.
- Corrected combined OS SHA-256:
  `e16da350435bfc16bb1e6db23947f21a8eca2b17364e7f922b3e82298f2b2e10`.

Real-framework compilation reproduces all 92 original broker classes byte-exact.
All 54 classes outside the controller and 81,222 unrelated pre-DEX SystemUI
entries remain unchanged. Converted resources and the existing development
platform signer match the parent. AVB verification and actual packaged seven-file
readback pass; all six other OS roles retain their selected identities, including
the prior services correction. The host emulator and Wonad/StyX11 APKs are unchanged.

Compiled rejection controls and parser/checkpoint regressions pass 17 host tests.
The separate current-image evidence now records ten populated redocks, ordinary
fixture/IME checks and full API operation/callback/capability exercise, with an
independent actual-image/layer/OS-hash audit. Reporting limitations are explicit
in its README; the original records remain unchanged. These bounded observations
do not replace genuine-failure, preserved-data, quiet-frontend or independent
review gates, and do not prove the separate intermittent click failure resolved.
