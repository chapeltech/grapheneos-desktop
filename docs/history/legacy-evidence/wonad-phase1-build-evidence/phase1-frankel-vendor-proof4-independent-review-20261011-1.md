# Phase 1 Frankel vendor CREATE-only proof 4 independent review

Date: 2026-10-11

Evidence directory:
`phase1-frankel-vendor-create-only-20261011-4`

This review authenticates a Docker **CREATE-only** profile and exact-owned
container cleanup. It is not vendor preparation, a download, an extraction, a
compiler/build run, OS staging, signing, a guest run, or runtime qualification.

## Bound evidence

- `receipt.json`: SHA-256
  `47e2d933cde63e7c3f442fd25d1c5399066ac3dcc746b7d131922212c38d30b4`.
- `command.json`: SHA-256
  `6a2b89b79092d912479998d58802bc2a326dc8f2789c8e4159fb7e6a4702da7c`.
- `inspect.json` and byte-identical `pre-removal-inspect.json`: SHA-256
  `640724bac8e664aa1931d59c000240e9f0008f7e9720d58970ab9ac9a69a50b6`.
- `cleanup.json`: SHA-256
  `22cc525cc7203b61e735ef1d8d2e405c40da28cada85066702eec764a0592c8c`.
- `tests.json`: SHA-256
  `f5d00738866274689132d93bb2321606e10b72611c62cab719f31b3886dff752`.
- Frozen helper: SHA-256
  `b9daf74f7b3716d7c6447dcafb14e46bb4ba6c7fdccd2360d243cdb878f0c6bf`.
- Frozen launch driver: SHA-256
  `a0129fddac134ac036ddd4d5c6d63faa8e5a614f376ff3968e5e2c642e20b16d`.
- Frozen tests: SHA-256
  `9a3f9a6fb36f6ec40e743014b998d650e1855b27d6f24533916c647a6ad67386`.

Strict JSON loading, receipt references, file sizes and hashes, exact container
identity, nonce, and pre/post-cleanup relationships were replayed read-only.

## Complete Wonad-side preparation closure

The helper binds the eight local files actually used by this `prepare-vendor`
path:

- `android/grapheneos.lock.json` —
  `ad259dde404f13a9d24e394b6ef8b19301ae436071316867ef1219e98f7486d6`;
- `android/platform/allowed_signers` —
  `344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0`;
- `android/platform/release-build.sh` —
  `756561b653494734861442cc0f05a57775ce36d2d13e96ab98b6de71ebf8c47c`;
- `android/tools/phase1_provenance.py` —
  `b0b0708f3405e6ea6b8fdb4fdd0abf8120208259a398bea12010b944a930fb50`;
- `android/tools/docker_locality_proof.py` —
  `09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780`;
- `android/tools/verify_sources.py` —
  `478a9fc83f7d316918487880383b11a39540ce28c40b2722f9f0fd9c312cbcf8`;
- `android/tools/verify_checkout.py` —
  `72a2fc049c11236dc010b52a53b3d0722be0898ff906b215131b23e0d9d5dd39`;
- `android/tools/checkout_health.py` —
  `168d309707daf8f30dfcf8785d43359effc8ec99e6c523a9de1ebdaf82376fa2`.

This closes the earlier proof omissions of the signer allowlist and the directly
imported Docker-locality helper. The receipt additionally content-binds the
Frankel manifest, build index, common and device configuration, vendor spec,
Yarn lock, and current vendor-state file, as well as the helper and driver.

## Actual CREATE-only profile

The immutable builder image is
`sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33`.
The created container was named
`wonad-phase1-frankel-vendor-create-only-20261011-4`, with exact ID
`97512d39d796eee4f823e0af486821433fb2e640be524a3c1566e76262df21a6`.
Both retained inspections show Created state, PID 0, zero start/finish times,
Running false, and no OOM event: it was never started.

The inspected limits are four CPUs (`0-3`, 4,000,000,000 NanoCPUs), 32 GiB
memory with `MemorySwap == Memory` (no extra swap), 2,048 PIDs, and a 4 GiB
`/tmp` tmpfs. The root filesystem is read-only. The command has the intended
source write bind and Wonad read-only bind set, no unexpected extra bind,
bridge networking with no published ports, no added capabilities, all
capabilities dropped, and `no-new-privileges`. Bind-list normalization is order
independent but still requires exact count and set.

## Exact-owned cleanup

The helper authenticated the exact name, ID, and nonce before removal. Raw
operations and observations are retained:

- `remove-result.json` SHA-256
  `bc0015282ad7efa2c2fb4c48efafc0f087de1725e04c39eccd8f64a677cf9d92`:
  exact-ID `docker container rm`, status 0, stdout exactly the ID plus newline,
  empty stderr;
- `name-absence.json` SHA-256
  `c8aede46f87d87c273a591e39c1d4cbd266beff13d645dd4229bf6045f7fda6c`:
  post-removal exact-name inspect, status 1 with the matching no-such-container
  diagnostic; and
- `id-absence.json` SHA-256
  `560ba59c90f24e874e17d85a3f1081e0410c4bac3afaa4e2a7d94ac55e958f8c`:
  post-removal exact-ID inspect, status 1 with the matching diagnostic.

The raw stdout and stderr files for all three operations are also retained and
content-bound by the cleanup records.

## Focused checks and limits

The retained pure suite reports eight tests passed, including 49 profile
mutation rejections and eight admission rejection cases. Shell syntax passed.
The recorded read-only admission observation passed at that instant, but did
not reserve CPU, memory, disk, source, or Docker capacity and grants no
authority to run vendor preparation. Historical refusal while an x86 lane was
live remains separately preserved in proof 3 and is not relabelled as proof 4.

No vendor command was executed and no network download, extraction, compilation,
build, guest, or product qualification occurred. The resource limits are
conservative admission/profile values; actual vendor peak usage remains
unmeasured.
