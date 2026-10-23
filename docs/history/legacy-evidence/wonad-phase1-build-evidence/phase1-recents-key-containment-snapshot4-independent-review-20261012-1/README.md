# Snapshot 4 independent containment review

This is a bounded source/JVM review of the immutable external proposal at
`phase1-recents-key-containment-kotlin-prototype-20261012-snapshot-4`
(aggregate file-ledger SHA-256
`c5096dd5c61e6e2db96742d66e484a37895c2c00dd5dc8dcfbb972c01afdb7dc`).
It is not Android compilation or runtime evidence, and no repository, staged
OS source, SDK, image, guest, or running service was changed.

## Confirmed defect

Claim lifecycle cleanup removes the exact Kotlin owner synchronously, but the
generated KGC cleanup listener posts the returned cleanup decision to
`mHandler`. A replacement key can install a new exact helper owner and set the
legacy Java stock mirror before that old runnable executes. The runnable
carried the old identity but ignored it when clearing the global Boolean.

The deterministic fixture composes the exact snapshot-4 helper with the exact
generated Meta cleanup rule:

- `AsyncCleanupReplacementRepro.kt` SHA-256
  `f1ea5bd8cece43b3135e127f2d681a96133246b1e04711c423a41eefd2245efa`
- observed stdout:
  `CONFIRMED delayed old cleanup suppresses exact replacement Meta completion`

The same defect class affected Caps. For Alt-Tab, the stale true Boolean could
reject replacement admission before an owner was created, and a delayed old
completion could hide replacement UI. APP_SWITCH cleanup was separately
protected by the exact thread-local PWM dispatch owner. Escape removal selected
the exact old message, and the pinned Shell handler ignores cancelled quit
events; those paths were not classified as replacement-clobber defects here.

## Bounded execution

The fixture and snapshot helper were compiled with the custom7 source-matched
toolchain:

- `external/kotlinc/bin/kotlinc` SHA-256
  `64d62a197fbec5f32f77c6724cce33ead4034b2ec3f873c056cde19fe00f324e`
- `prebuilts/jdk/jdk21/linux-x86/bin/java` SHA-256
  `cfa21aeadd00925925c9e1287f5c08f3e04ee7f26a9e23d9dbfb16149153d842`
- compiler heap `256 MiB`; JVM heap `128 MiB`

This result does not claim a full-platform compile, real input-thread timing,
Android Binder/Looper behavior, or runtime qualification.
