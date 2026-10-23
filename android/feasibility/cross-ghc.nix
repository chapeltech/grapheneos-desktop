# Toolchain experiment, not an approved production compiler pin.
# This revision is used by the SimpleX Android GHC 9.6.3 build. The build may
# download substantial dependencies; it is deliberately separate from Gradle.
let
  haskellNix = builtins.getFlake
    "github:input-output-hk/haskell.nix/d0c35e75cbbc6858770af42ac32b0b85495fbd71";
in
  haskellNix.legacyPackages.x86_64-linux.pkgsCross.aarch64-android
    .buildPackages.haskell-nix.compiler.ghc963
