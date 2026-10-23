#!/usr/bin/env bash
# Literal Frankel vendor-cache preparation successor. Default: read-only check.
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
  echo 'usage: prepare-phase1-frankel-vendor-cache-20261011-4.sh [--check-only|--run|--create-only-proof]' >&2
  exit 2
fi
case "$1" in
  --check-only|--run|--create-only-proof) ;;
  *) echo 'refusing unsupported argument' >&2; exit 2 ;;
esac
exec /usr/bin/python3 -B \
  /u/elric/tree/wonad-phase1-build-evidence/phase1_frankel_vendor_cache_driver_20261011_4.py \
  "$1"

