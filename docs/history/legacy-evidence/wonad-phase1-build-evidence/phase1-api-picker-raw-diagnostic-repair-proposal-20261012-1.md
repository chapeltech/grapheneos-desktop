# API picker diagnostics: bounded host-only proposal

This is distinct from the Launcher focus-routing OS proposal. No source, SDK,
APK, image, or guest has been changed or rerun. Current input is
`android/tools/conformance_smoke.py`, SHA-256
`d193c2641d3ceebb7bc498308181a4d0b02b0d0701544e343ad059b4917b3dd5`.

## Actual gap

Pair7 reached a client `showTransferPicker` request and `wait-transfer-back`.
It never proved a secure, drawn and natively focused phone picker. Inner
`Device.call` results from `dumpsys window displays`, `dumpsys window windows`,
and the bracketing service-status reads are consumed without retention.
The final AFTER status read exceeded its remaining 0.040295577-second budget.
That timing does not reveal which prior Window predicate was false. No ESCAPE
was issued by the successful branch: that branch returns immediately.

## Smallest prospective host correction

Keep the complete current `focused_transfer_picker` recognition function,
its exact title/token/user/owner/display/security/drawn/visibility checks,
the 15-second picker deadline, the 3-second per-command cap, before-and-after
exact-run/phase checks, and sole display-0 ESCAPE-on-proof branch unchanged.
Do not add a focus override, settings write, retry, stale fallback, permissive
window parser, longer deadline, or substitute a blocked client callback for
native Window proof.

Add a picker-scoped diagnostic journal emitted synchronously to the existing
captured stdout as one tagged JSON line per event. Prefix the line with
`WONAD_PICKER_DIAGNOSTIC ` so it cannot masquerade as a conformance status.
The existing outer command already captures stdout in `conformance.log` and
the command journal on failure; this avoids a new userdata-only artifact and
does not require changing the producer/report format for basic retention.

The journal begins before the package-UID read and records:

- campaign run/nonce, diagnostic sequence, monotonic start/end and deadline;
- exact argv, remaining/per-command timeout, return code or explicit timeout;
- raw merged stdout bytes (base64 or exact UTF-8 plus raw byte identity), byte
  count and SHA-256, including partial output on timeout/nonzero exit;
- decoded raw bracketing statuses without floating-point conversion of
  generation/token integers;
- each native `window displays` and `window windows` observation before
  evaluating the unchanged predicate;
- the predicate result and specific rejection categories, including absent
  or ambiguous phone section/focus row, wrong user/title/token, global focus,
  dialog count, owner UID/package, attributes/type/security, surface/drawn,
  on-screen/visible, and status run/phase changes;
- the sole cancellation input only after the same successful predicate;
- an honest final timeout/error/completion event before exception propagation.

No journal entry is a PASS or a replacement for ordinary UI/native focus proof.
Diagnostics must retain failed samples before testing or raising. In particular,
a timeout's partial output is recorded and the original timeout is re-raised.

## Bounds and failure behavior

Proposed explicit bounds are at most 128 diagnostic events, 512 KiB raw output
per observation, and 4 MiB total encoded journal. Budget exhaustion or oversized
output records an explicit bounded failure and exits before another input or
predicate-based cancellation; it must not silently crop a sample then use it as
proof. This bounds retention, not peak RSS of the current `subprocess.run`
capture. An exact bounded streaming command reader, if desired, is a separate
reviewed addition and is not silently claimed by this proposal.

The remaining deadline is checked before every command and no diagnostic call
adds a sleep or resets the deadline. Diagnostic timing is distinct from Android
elapsed-realtime values. Cleanup of an owned host adb process must not be
labelled proof that the Android instrumentation/service stopped.

## Focused prospective tests

Use the exact unchanged recognition method and mocked host command results:
secure matched picker produces one ESCAPE; every original rejection produces
no input and a retained reason. Compare actual predicate true/false to the reason
classifier, including malformed/null/duplicate rows and actual retained phone
and external-display formats. Test timeout partial bytes, nonzero exit, no output,
oversize and aggregate exhaustion, negative/malformed bounds, expired budget
before action, and big generation integers. Assert all required raw samples occur
in recorded order before the decision, the final failure remains primary, and
tagged lines cannot satisfy `terminal_status_from_log`. No live ADB/VM is needed.

The actual secure Window observations are still unavailable for API7. A future
fresh authorized campaign, after source/image binding, is needed to diagnose its
unique native focus/visibility cause. This proposal is not that evidence.
