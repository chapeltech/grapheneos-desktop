#!/usr/bin/env bash
# Run inside the pinned builder, with a dedicated writable OS checkout.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source_dir=${WONAD_GRAPHENEOS_SOURCE:?Set WONAD_GRAPHENEOS_SOURCE to a dedicated OS checkout}
action=${1:-build}
case "$action" in sync|build) ;; *) echo 'Usage: source-build.sh sync|build' >&2; exit 2 ;; esac
source_dir=$(realpath -m -- "$source_dir")
case "$source_dir" in /|/sources|"$root"|"$root"/*) echo 'Use a dedicated source directory outside Wonad' >&2; exit 2 ;; esac
jobs=${WONAD_BUILD_JOBS:-8}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid job count' >&2; exit 2; }
highmem_jobs=${WONAD_BUILD_HIGHMEM_JOBS:-1}
[[ "$highmem_jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid high-memory job count' >&2; exit 2; }
# Metalava's pool otherwise sizes itself from host RAM, not our container limit.
# Several simultaneous framework API generators can exhaust a 48 GiB builder.
export NINJA_HIGHMEM_NUM_JOBS="$highmem_jobs"
sync_jobs=${WONAD_SYNC_JOBS:-2}
[[ "$sync_jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid sync job count' >&2; exit 2; }
sync_network_jobs=${WONAD_SYNC_NETWORK_JOBS:-4}
[[ "$sync_network_jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'Invalid sync network job count' >&2; exit 2; }
((sync_jobs <= 256 && sync_network_jobs <= 32)) || {
    echo 'Sync job limits exceed reviewed bounds' >&2; exit 2;
}
release=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["release"])' "$root/android/grapheneos.lock.json")
repo_revision=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repo_tool"]["revision"])' "$root/android/grapheneos.lock.json")
repo_commit=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["repo_tool"]["commit"])' "$root/android/grapheneos.lock.json")
mkdir -p -- "$source_dir"
cd -- "$source_dir"
if [[ "$action" == sync ]]; then
    if [[ ! -d .repo ]] && [[ -n "$(ls -A)" ]]; then
        echo 'Refusing to initialize an occupied non-repo directory' >&2; exit 2
    fi
    # repo uses this identity only for its local manifests, not published commits.
    export GIT_AUTHOR_NAME='Wonad build' GIT_AUTHOR_EMAIL='build@wonad.invalid'
    export GIT_COMMITTER_NAME="$GIT_AUTHOR_NAME" GIT_COMMITTER_EMAIL="$GIT_AUTHOR_EMAIL"
    repo init -u https://github.com/GrapheneOS/platform_manifest.git \
        -b "refs/tags/$release" --repo-rev="$repo_revision" \
        --depth=1 --partial-clone --clone-filter=blob:limit=10M
    [[ $(git -C .repo/repo rev-parse HEAD) == "$repo_commit" ]] || {
        echo 'Unexpected repo tool revision' >&2; exit 2;
    }
    python3 "$root/android/tools/verify_sources.py" --manifest .repo/manifests \
        --manifest-only --allowed-signers "$root/android/platform/allowed_signers"
    if [[ -n "$(git -C .repo/manifests status --porcelain --untracked-files=no)" ]] ||
        [[ -d .repo/local_manifests ]]; then
        echo 'Refusing modified manifests or local overrides in the baseline sync' >&2; exit 2
    fi
    # No --force-sync: never discard local platform work during a resumed sync.
    # AOSP throttles high fan-out fetches independently of local checkout
    # parallelism. Retry only transient fetches and keep the network pool
    # bounded while allowing this large checkout to populate worktrees fast.
    repo sync -c -j"$sync_jobs" --jobs-network="$sync_network_jobs" \
        --retry-fetches=3 --no-tags --fail-fast
fi
test -f build/envsetup.sh || { echo 'Complete source sync first' >&2; exit 1; }
python3 "$root/android/tools/checkout_health.py" --source "$source_dir"
python3 "$root/android/tools/verify_sources.py" --manifest .repo/manifests \
    --frameworks frameworks/base --allowed-signers "$root/android/platform/allowed_signers"
if [[ "$action" == sync ]]; then
    python3 "$root/android/tools/verify_checkout.py" --source "$source_dir" --jobs 32
fi
if [[ "$action" == build ]]; then
    if [[ -n "${WONAD_APK_CERTIFICATE:-}" ]]; then
        python3 "$root/android/platform/stage-os.py" --source "$source_dir" \
            --signer-certificate "$WONAD_APK_CERTIFICATE" --input-profile emulator
    elif [[ -e external/wonad ]]; then
        echo 'Set WONAD_APK_CERTIFICATE to the selected public release X.509 certificate' >&2
        exit 2
    fi
    bash "$root/android/platform/apply-emulator-config.sh"
    # envsetup is not compatible with nounset.
    set +u
    # shellcheck source=/dev/null
    source build/envsetup.sh
    lunch sdk_phone64_x86_64-cur-userdebug
    unset OFFICIAL_BUILD
    export BUILD_NUMBER="wonad.$release"
    BUILD_DATETIME=$(git -C .repo/manifests show -s --format=%ct HEAD)
    export BUILD_DATETIME
    m -j"$jobs"
fi
