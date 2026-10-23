# Native baseline attempt 5 — terminal, not qualification

On 2026-10-11 at 12:43 UTC, unified execution session 49733 returned exit 2.
Foreground PID 3426056 and its owned source-verification child are gone.
The actual terminal diagnostic was:

```text
phase1_generic_upstream_evidence.py: Full AOSP-host tests require at least 44 GiB available RAM; wait for competing builds to finish
```

The source-verification child completed before test execution. At about 12:40
UTC root observed the parent at 57,640 KiB RSS with a 140,136 KiB high-water
mark, after the child's approximately 1.9-GiB arenas had been released. This
demonstrates that bounded child lifetime avoided that source-audit retention;
it does not prove adequate memory for the complete native campaign.

Both actual Blueprint invocations completed. Their retained native JSON event
streams independently replay through the current strict parser to 2,621 passed
and 11 skipped ledger entries each. Entries include package terminals and are
not exclusively individually named tests. Both retained container observations
record exit code 0, no timeout and no OOM, with exact owned cleanup:

- normal ID `d6e19cd82e6a09259e8c7cc61d1598118b40efbe06c31c693e65dfe3b4d328ab`;
- race ID `b2d0fee2a0f615d8ebd06086fa468b3a341dbba8cb57b33d5b502dd0395e1be8`.

Their IDs and names were proven absent by the runner and remained absent in
root's postflight Docker query. The 44-GiB admission guard rejected the next
invocation before normal Soong created a container or output stream. The exact
rejection-time MemAvailable value was not recorded; the later postflight value
must not be substituted for it. Root observed 46,329,936 KiB after termination.

The authenticated disposable workspace cleanup removed 4,020 entries containing
399,615,528 bytes. Its device/inode was `64513/174921605`, UID/GID `1000:1000`.
The exact owned workspace and same-parent quarantine are both absent. Cleanup
receipt `aosp-baseline/cleanup.json` has SHA-256
`fd1fe89afedaf2596f088ecb854e2441f9099f814f3ad80d95fb83c9e66de62b`.
Only this attempt's disposable test workspace was removed; original logs,
container records, preparation snapshots and all receipted source/build OUT
inputs remain separate and unchanged.

The original `PREPARATION.json` and thirteen helper/test/plan/build-receipt
snapshots are preserved. No complete host receipt exists: the remaining eight
normal/race invocations and post-run source/build/OUT authentication did not
execute. Do not combine partial attempts into a passing campaign, weaken the
44-GiB floor, shorten normal Zip64 coverage or restart this terminal handle.
