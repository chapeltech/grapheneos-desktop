#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
: "${WONAD_ANDROID_GHC:?Set WONAD_ANDROID_GHC to an Android GHC cross compiler}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed Android NDK}"
abi=${WONAD_ANDROID_ABI:-x86_64}
case "$abi" in
    x86_64) arch=x86_64 ;;
    arm64-v8a) arch=aarch64 ;;
    *) echo "Unsupported Android ABI: $abi" >&2; exit 2 ;;
esac
target=$("$WONAD_ANDROID_GHC" --info)
# GHC 9.12 normalizes Android's Target platform OS to Linux, but retains
# the full Android triple in LLVM target (including when using its native CG).
if ! [[ "$target" =~ \"(Target\ platform|LLVM\ target)\"[[:space:]]*,[[:space:]]*\"$arch-[^\"]*android[^\"]*\" ]]; then
    echo "Refusing GHC not targeting Android $abi; desktop Linux is not Android." >&2
    exit 2
fi
ndk="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
test -f "$ndk/sysroot/usr/include/jni.h" || { echo "Missing NDK JNI headers" >&2; exit 2; }
out="$root/android/out/android-native/$abi"
mkdir -p "$out/objects"
# The cross compiler and its base/RTS dependencies must have been built as PIC
# for Android. Do not paper over TEXTRELs, glibc dependencies or missing symbols.
# Compile C separately with an explicit output: GHC's --make -odir does not
# redirect C intermediates away from a read-only source checkout.
"$WONAD_ANDROID_GHC" -c -fPIC -I"$ndk/sysroot/usr/include" \
    "$root/android/feasibility/probe_jni.c" -o "$out/objects/probe_jni.o"
"$WONAD_ANDROID_GHC" --make -O1 -Wall -Werror -fPIC -shared -threaded \
    -no-hs-main -flink-rts \
    -I"$ndk/sysroot/usr/include" \
    -optl-Wl,-z,defs -optl-Wl,-z,max-page-size=16384 \
    -optl-Wl,-u,wonad_probe_layout -optl-Wl,-u,wonad_probe_stress \
    -optl-Wl,-u,JNI_OnLoad \
    -odir "$out/objects" -hidir "$out/objects" -stubdir "$out/objects" \
    "$root/android/feasibility/NativeProbe.hs" \
    "$out/objects/probe_jni.o" -o "$out/libwonad_probe.so"
python3 "$root/android/tools/check_native.py" \
    --abi "$abi" --readelf "$ndk/bin/llvm-readelf" "$out/libwonad_probe.so"
