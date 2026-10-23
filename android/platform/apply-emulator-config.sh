#!/usr/bin/env bash
# Emulator-only capability, hardware keyboard, and display-buffer ownership.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source_dir=${WONAD_GRAPHENEOS_SOURCE:?Set WONAD_GRAPHENEOS_SOURCE to the OS checkout}
goldfish="$source_dir/device/generic/goldfish"
patches=(emulator-freeform.patch emulator-meta-keys.patch emulator-front-buffer-lifetime.patch)
targets=(64bitonly/product/sdk_phone64_x86_64.mk input/qwerty2.kl MultiDisplayProvider/jni/com_android_emulator_multidisplay.cpp)
pending=()
# Preflight every target before applying any patch. Existing owned patches
# may be present when upgrading an earlier demo checkout.
for index in "${!patches[@]}"; do
    patch_file="$root/android/platform/patches/${patches[index]}"
    if git -C "$goldfish" apply --reverse --check "$patch_file" 2>/dev/null; then
        echo "Wonad ${patches[index]} already present"
        continue
    fi
    if ! git -C "$goldfish" diff --quiet HEAD -- "${targets[index]}"; then
        echo 'Refusing to modify an independently changed emulator configuration file' >&2
        exit 2
    fi
    git -C "$goldfish" apply --check "$patch_file"
    pending+=("$patch_file")
done
for patch_file in "${pending[@]}"; do
    git -C "$goldfish" apply "$patch_file"
done
echo 'Enabled emulator freeform, Meta keys, and front-buffer retention; no permission or SELinux checks changed'
