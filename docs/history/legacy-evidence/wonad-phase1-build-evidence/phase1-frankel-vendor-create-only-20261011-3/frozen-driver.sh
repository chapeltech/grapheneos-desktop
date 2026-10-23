#!/usr/bin/env bash
# Literal, first-attempt Frankel vendor preparation. Default: read-only check.
set -euo pipefail
export PATH=/usr/bin:/bin
export LANG=C
export LC_ALL=C
export PYTHONDONTWRITEBYTECODE=1
umask 077
if (($# == 0)); then
  set -- --check-only
fi
exec /usr/bin/python3 \
  /u/elric/tree/wonad-phase1-build-evidence/phase1_frankel_vendor_driver_20261011_1.py \
  "$@"
