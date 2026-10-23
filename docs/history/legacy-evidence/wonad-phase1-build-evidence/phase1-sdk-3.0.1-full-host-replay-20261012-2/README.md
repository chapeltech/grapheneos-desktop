# SDK 3.0.1 successor host replay

This is external, captured Python-host evidence for the second SDK 3.0.1
integration candidate. It did not modify the live Wonad repository or current
SDK, and it did not start Docker, Gradle, a JVM, an emulator, a VM, an APK/OS
build, or a signing ceremony.

`base/` and `hardened/` each contain the same exact 798-path dependency/source
closure. `results/inputs.json` inventories every file and proves an exact
14-path overlay matching candidate 2's integration map. The overlay includes:

- independent native-auditor derivation of all three normative member
  SHA-256/size/mode rows from the already inventory-bound sealed contract ZIP;
- exact-string SHA-256 validation in native compile and client provenance;
- permanent controls rejecting an alternate valid 64-hex member digest,
  numeric digest coercion, malformed/extra/duplicate ZIP members, and changed
  ZIP mode/timestamp;
- the corrected exact release-receipt fixture.

The guarded replay ran six modules, 192 tests, with zero failures, errors, or
skips in 37.122133 seconds. Only Git, Git LFS, OpenSSL, the current Python, and
temporary fixture-local `apksigner` scripts were permitted as subprocesses.
Tests use synthetic archives, temporary test Git repositories, and ephemeral
self-signed test certificates; this is not Android/JVM ABI, real publication,
production signing, stage/build, runtime, or release qualification.

The predecessor remains untouched:

- candidate-1 receipt: `968c2e810e70f7785e6c12fc60e66a4fa88faa076199451cffb47a6874085fd7`;
- expected-RED binding probe result: `8bacb49525cf8979340357672d026714e76c0110ce5f1ddf604cac5b52b15ae7`;
- corrected predecessor replay result (189/189):
  `a145476a04b9193db8c919a38a82be9860c2e562cda12c1976dafc4cc503f3fa`.

No 3.0.1 artifact hash is known or asserted. Canonical 3.0.0 identities remain
historical and distinct; a fresh stage, two real independent publications,
OS/client rebuilds, runtime campaign, and release evidence are still required.
