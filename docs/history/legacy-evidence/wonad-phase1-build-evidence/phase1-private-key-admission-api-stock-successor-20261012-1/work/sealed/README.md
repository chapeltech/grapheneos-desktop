# Private admission seam and null-focus STOCK successor

2026-10-12. External-only selected post-target source/host repair, not integrated,
not a native/framework Android build or runtime/device qualification.

The immutable predecessor is preserved at ../before (manifest SHA-256
512be7775dc1874fea65ad1868848fe3c89d70fc246cbf8b0b8709f812f55975).
Its claimed null-focus fail-close was correct, but its adapter also consumed
unclaimed/phone null-focus DOWN/UP, and it removed the existing internal
three-argument KGC method used by pinned platform tests. This successor fixes
both without modifying the predecessor, repository, source7, stages, SDK,
images, keys or runtime.

## Narrow changes

The adapter now requires focus only when the immutable observation request
contains a current or retained claim. A phone/unclaimed event with no claim
and null focus remains STOCK, while a claimed null-focus DOWN remains CONSUME
and drains its matching terminal even if focus appears. Initial STOCK DOWN
authority still wins over later claim publication, including null-focus UP.

KGC retains the internal three-argument overload. Its exact body delegates to
the private four-argument method with token0. This is not a native admission
surface: zero cannot produce accepted -3 and there is no AdmissionCall owner
for a direct compatibility invocation. IMS continues to invoke the four-arg
private seam with native nonce and an exact begin/finish AdmissionCall wrapper.
No public SDK, Binder or app-facing KeyEvent field changes.

The pinned tests/Input/KeyGestureControllerTests.kt hash is
f14238927f72d9b8939fcf1f707d7f7c869490146d8b3125b86d9f82932b7077.
Its actual inventory is fifteen direct KGC three-arg call expressions (the
other grep matches are unchanged two-arg WindowManagerCallbacks). The host
signature fixture extracts every actual pinned direct call and the generated
actual compatibility method, compiles Java/Kotlin together against tiny stock
type stubs, and verifies all fifteen calls delegate token0. This establishes
private caller signature compatibility, not execution of the full Android
platform test class. Claimed host controls retain explicit nonzero native
nonce + AdmissionCall setup/commit/finally ownership.

All other predecessor private nonce, native ownership, reset/release/JNI
exception/reentrancy controls remain included. Ordinary STOCK shortcut method
bodies remain byte-equal to source7 and the retained native patch is unchanged.

## Evidence and limits

work/sealed is the final read-only payload. MANIFEST.json binds originals,
target hashes, source/test pins, generated Java/Kotlin/native source, two JVM
control JARs, the extracted native projection binary, Java/Kotlin signature
fixture classes/JAR, and ordered base/native/integration patches.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1-private-key-admission-api-stock-successor-20261012-1/work/sealed/test_candidate.py
```

Heap caps remain Kotlin256MiB/JVM128MiB. Native projection is g++ C++20.
The STOCK caller projection uses the pinned JDK javac plus Kotlin/JVM tools.

The raw INVALID-display queue/policy/final-target F1-to-F2 gap remains OPEN.
No immutable reader device-incarnation origin is added. Physical-device,
pre-target PWM, final-target/display incarnation, cross-device safety chords
and cancellation collateral remain unqualified. Separate origin/final-target
architecture work is not included in this repair and is not waived.
Full platform compilation, actual VM/JNI execution and Android runtime remain
required. Nothing here is already in an image.

The initial producer seal/packaging rejection, snapshot14 six defects/seven
schedules, snapshot15 stale-focus/F1-to-F2 REDs and lifetime-review obligations
remain preserved in the predecessor evidence; no historical defect is deleted.
