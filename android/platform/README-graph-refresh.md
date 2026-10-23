# Guarded Soong graph refresh

`refresh-soong-graph.py` refreshes an existing Android Soong graph with the
non-interactive equivalent of `m -jN nothing`, without allowing Siso to replace
the incremental history used by subsequent direct-Ninja builds. Use it before
`direct-target-build.sh` when staged sources changed which files a Soong glob
must discover.

Example (all build coordinates are intentionally explicit):

```sh
android/platform/refresh-soong-graph.py \
  --source /absolute/path/to/grapheneos \
  --out out \
  --graph out/combined-sdk_phone64_x86_64.ninja \
  --target-product sdk_phone64_x86_64 \
  --target-release cur \
  --target-build-variant userdebug \
  --build-number wonad.RELEASE \
  --build-datetime MANIFEST_COMMIT_EPOCH \
  --highmem-jobs 1 \
  --jobs 8
```

The helper validates that the checkout, output directory, graph, and
in-checkout Soong launcher are direct, non-symlink paths. It removes inherited
output and Ninja-option variables and supplies `OUT_DIR`, lunch coordinates,
build number, build epoch, and high-memory pool size from the command line.

Before Soong starts, `out/.ninja_log` and `out/.ninja_deps` are moved—not
copied—into an output-local journal. This preserves their bytes, inode,
ownership, mode, modification time, and extended attributes. Each original is
moved back with an atomic same-filesystem rename whether `m nothing` succeeds,
fails, or receives `SIGHUP`, `SIGINT`, or `SIGTERM`. The graph is validated
again on a successful refresh. An interrupted journal is recovered before
another refresh can start; use the same arguments plus `--recover-only` to
recover without requiring a usable graph or invoking Soong.

Limitations:

- The output directory must be exclusively owned by this refresh while it
  runs. The lock prevents two copies of this helper, but cannot stop unrelated
  build commands from modifying the same output tree.
- Only direct Ninja's `.ninja_log` and `.ninja_deps` are protected. A failed or
  killed Soong run can leave other generated graph/output files changed; the
  helper does not claim to roll those files back.
- `SIGKILL`, host failure, or power loss cannot run an in-process cleanup. The
  durable journal makes recovery resumable on the next invocation. The direct
  Soong child inherits the advisory lock, so a killed wrapper cannot let a new
  invocation restore history underneath an orphaned refresh: recovery remains
  locked out until that child exits. A crash before the journal's commit rename
  can leave a harmless hidden `.prepare.*` directory containing no moved
  history.
- The remaining ambient process environment (for example `PATH`, `HOME`, and
  pinned-container toolchain settings) is inherited. Run this inside the same
  pinned builder environment as the original graph generation.
- The helper invokes `build/soong/soong_ui.bash --make-mode` directly instead of
  sourcing `envsetup.sh`; its argument and environment are the expansion of
  `m -jN nothing`, not an interactive `lunch` session.

