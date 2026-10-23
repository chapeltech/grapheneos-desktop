# Custom6 native app-input lease-loss negative control

This directory preserves the exact standalone compiled regression before the
production correction. It is historical source evidence, not runtime or image
qualification.

- Source fixture: `test_native_app_input_lease_loss_compiled.py`
- SHA-256: `9a62755d3fed4c4590c4347fbaf57348275b3bdde9e9d790be5825c9ef3d6b2a`
- Command:
  `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=android/tests python3 -m unittest -v test_native_app_input_lease_loss_compiled`
- Observed result on 2026-10-11: one test ran and failed after successful
  Kotlin compilation. The fixture process exited at the exact assertion
  `sticky native display without a valid lease must drop newly populated app input`.
- The phone, unclaimed external-display, and live claimed-display controls ran
  before that terminal assertion and did not fail.

The production source used by this reproduction was byte-identical in the
workspace and frozen custom6 stage, SHA-256
`aeb2e4788d6037f0ebd09b354a67a78db772582a6a72627bcb61d4993e8432a8`.
