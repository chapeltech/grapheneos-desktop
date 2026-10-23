# Launcher3 display-cache correction — original proposal retained

`recents-display-task-cache.patch` is the historical proposal copy used by the
original compile receipts. The byte-identical canonical
`patches/wonad-recents-display-task-cache.patch` is now registered as the sixth
Launcher patch. Preserve earlier receipts and inventories under their original
identities; the [successor source review](../PHASE0-RECENTS-SOURCE-REVIEW.md)
binds the new image without restaging old sources.

The [original evidence and bounded host reproduction](../../out/phase0-recents-cache-diagnosis-20261019-1/README.md)
show a phone Screenshot failure and a concrete upstream task-cache defect.
The source-matched reproduction compiles the actual history/getter bodies with
explicit host dependency doubles. External HOME events can evict a still-running
phone task; global three-task queries can also omit the requested display.

The proposal scopes both existing queries by display and uses a bounded fresh
display-specific query when nonempty history has lost that display. A miss does
not rewrite the global history or grow its registry. Existing task filtering and
the shell-tracking branch remain unchanged. It adds no desktop policy, API,
privilege, permissions, screenshot-policy bypass or phone-focus intervention.

Compilation against the actual pinned Launcher3/framework now passes. The
original two classes, post-Jarjar classes and both R8 DEX files reproduce the
retained build byte-for-byte. The corrected APK keeps the original development
certificate and 1,041 unrelated APK entries unchanged. An AVB-verified OS
package contains the corrected Launcher and preserves all seven checked OS
roles plus MultiDisplayProvider. These are build controls, not runtime proof.

The proposed upstream Java delta is nine added / three removed lines in one
existing file. It adds no owned Java, changes no public SDK or authority, and
does not bypass screenshot-policy checks. The display-miss query is ephemeral:
it neither grows the global task history nor selects or moves a window.

The [packaged candidate](../../out/phase0-recents-cache-candidate-20261019-1/README.md)
passes the real-Qt/XTEST Recents actions and acceptance checks: the original
phone task retains Screenshot/Split menu items after final unplug and
three-monitor redock, and all native transfers/input checks pass. The evidence
discloses three earlier harness enhancements; the new diagnostic-read retry
branch was unused. Do not call the harness files byte-identical to the negative
run, or menu presence full Screenshot/Split functionality qualification.

The [shipping-launcher/stock-action check](../../out/phase0-recents-handoff-20261019-1/README.md)
also saves the actual 1080×2400 phone app Screenshot and exercises native Split
screen with per-pane physical input. APK update, consent/data persistence and
cold restart pass. The original pending-file test-reader failure is preserved.
Actual user-X11 and later-phase qualification remain outstanding.
