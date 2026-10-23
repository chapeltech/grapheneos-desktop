#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
command -v nix >/dev/null || { echo "Nix is required for this isolated toolchain experiment" >&2; exit 2; }
mkdir -p "$root/android/out"
# Cache key published in the pinned haskell.nix getting-started documentation.
# These flags apply only to this invocation, not to the machine's Nix config.
options=(--extra-experimental-features 'nix-command flakes'
    --option cores 8 --option max-jobs 2
    --option extra-substituters https://cache.iog.io
    --option extra-trusted-public-keys 'hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ=')
# On 2026-09-30 the upstream cache lacked required outputs with no build
# recipe. Fail before expensive LLVM builds when Nix can detect this up front.
nix "${options[@]}" build --impure --dry-run --file "$root/android/feasibility/cross-ghc.nix"
exec nix "${options[@]}" build --impure --out-link "$root/android/out/cross-ghc" \
    --file "$root/android/feasibility/cross-ghc.nix"
