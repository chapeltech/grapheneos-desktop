#!/usr/bin/env bash
# Generation-6 bridge for the reviewed host/builder vendor boundary.
# Default operation is read-only admission. Root authorization is required
# before invoking --run.
set -euo pipefail
export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
umask 077

if (($# == 0)); then
  set -- --check-only
fi
if (($# != 1)); then
  echo 'usage: prepare-phase1-frankel-vendor-cache-20261012-6.sh [--check-only|--run]' >&2
  exit 2
fi
case "$1" in
  --check-only|--run) ;;
  *) echo 'refusing unsupported argument' >&2; exit 2 ;;
esac

exec /usr/bin/python3.14 -B /u/elric/tree/wonad/android/tools/run_frankel_vendor.py "$1" \
  --source /u/elric/tree/wonad-grapheneos-2026100600-frankel-baseline-1 \
  --repo /u/elric/tree/wonad \
  --builder-image sha256:f719a4a56095b613790ef9afcba2aabda795217ac98e08c24ba5cec65bd4ee33 \
  --adevtool-commit 17df3b79a73e67ad68387b35c7d41c85e1d8103c \
  --cache /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-factory-cache-20261011-1 \
  --cache-receipt /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-factory-cache-20261011-1/receipt.json \
  --cache-receipt-sha256 458273099a83f97c60ed6ba1a7a40e14704f850b04068443946ca65e78dbe6c3 \
  --archive-name frankel-cp3a.261005.005-factory-3721e6ac.zip \
  --factory-build-id CP3A.261005.005 \
  --archive-sha256 3721e6accc2e87d851ee7966d794318078ec74c7cc32343daa10968264d6bb62 \
  --archive-bytes 11378664978 \
  --work /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-vendor-cache-work-20261012-5 \
  --log /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-vendor-cache-20261012-6.log \
  --preflight /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-vendor-cache-20261012-6.preflight.json \
  --result /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-vendor-cache-20261012-6.result.json \
  --attempt-lock /u/elric/tree/wonad-phase1-build-evidence/phase1-frankel-baseline-vendor-cache-20261012-6.lock.json \
  --container wonad-phase1-frankel-vendor-2026100600-006 \
  --debug-id e5e8d4c4d2b1373416027fa86d88a5d9e6d6d3e3592c0b9cabcf80a6b59ffc4d \
  --debug-proof /u/elric/tree/wonad-phase1-build-evidence/phase1-custom7-preserved-debug-sleep-adb-proof-20261011-1.json \
  --debug-proof-sha256 49ee022282157cbe77b215660a8afcf98c75184872b1cb93b1e902f9c85d24f8 \
  --repo-input android/grapheneos.lock.json=ad259dde404f13a9d24e394b6ef8b19301ae436071316867ef1219e98f7486d6 \
  --repo-input android/platform/allowed_signers=344f59c6f058699e63fea68e35953b341c14e3bf1fbc1256f6baa84aa2aca1d0 \
  --repo-input android/platform/generate-frankel-vendor.sh=eb8155555900e68e3e53714d0ca40c5bbe55ad5fe6abea1c9d97393fda19b854 \
  --repo-input android/tools/checkout_health.py=168d309707daf8f30dfcf8785d43359effc8ec99e6c523a9de1ebdaf82376fa2 \
  --repo-input android/tools/docker_locality_proof.py=09b68ceabeb83ed997608a427f8bd5e4196a229d0e3ffd5fc59a98cff85da780 \
  --repo-input android/tools/phase1_provenance.py=b0b0708f3405e6ea6b8fdb4fdd0abf8120208259a398bea12010b944a930fb50 \
  --repo-input android/tools/run_frankel_vendor.py=35b2b23b94e9c29a87b21a87c3ff3f5a8bfb003ac797efc2040c524932ff55fc \
  --repo-input android/tools/verify_checkout.py=72a2fc049c11236dc010b52a53b3d0722be0898ff906b215131b23e0d9d5dd39 \
  --repo-input android/tools/verify_sources.py=478a9fc83f7d316918487880383b11a39540ce28c40b2722f9f0fd9c312cbcf8 \
  --source-input .repo/manifests/default.xml=32d30e70ee59d373a17fe8090bdded898afa80651f27c331caca4578b3008888 \
  --source-input vendor/adevtool/config/build-index/build-index-main.yml=a108c6dd08afe9ad5e3fe09f36ae513b2fac34c7d18a2a66d5a90ebb742933f4 \
  --source-input vendor/adevtool/config/device/common/gen10pixel.yml=92dd7f9cfdb3bdef2922892048f323407b6896f5e93f7ca8f73816488254ceca \
  --source-input vendor/adevtool/config/device/frankel.yml=2521e1a357d029336b4574c2ae9897dc4b9cf2cba729c6a3376bd65f705b79a1 \
  --source-input vendor/adevtool/src/commands/download.ts=a734b1570c8cd4099b242b8893de77ac6683a08e92f83eff5c19319044d27984 \
  --source-input vendor/adevtool/src/config/paths.ts=418823cca30a381208e13acd7ea30d5ff37be411f1492ccd05f290ba4c95bd8e \
  --source-input vendor/adevtool/src/frontend/source.ts=001de5cab8ae7524ba862135d7663a467a7b49ae0fea733d044090c40a728ca9 \
  --source-input vendor/adevtool/src/images/device-image.ts=f2a8a827b609dbf5bd31488de5b762eb6777408bd29c45521cefdc9d798bbfc0 \
  --source-input vendor/adevtool/src/images/download.ts=2d4384422de6c48999ed716024bb92e1a23efeb865a50cfdf7a45dec84c3ffee \
  --source-input vendor/adevtool/vendor-specs/google_devices/frankel.yml=d3e8ba76ad3711a101105278bb3217984061828dfd89fe34718f067a2cdf987c \
  --source-input vendor/adevtool/yarn.lock=69475c004b6271a3817e7c79bebf7459e9e3c80684864cd60bdf88d944904f8f \
  --source-input vendor/state/frankel.json=3c139de11a8bbe8f3f4fb16f339da60bfdbe598492d7f2b346bc3e68794d8759
